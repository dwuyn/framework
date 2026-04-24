#!/usr/bin/env python3
"""
HackSynth Custom Target Runner

A flexible penetration testing runner that supports custom targets
beyond CTF challenges. Supports multiple success criteria types,
optional Neptune logging, and interactive modes.

Usage:
    # Run with custom targets file
    python run_custom.py -t targets.json -c config.json

    # Run single target interactively
    python run_custom.py -t targets.json -c config.json --target my_target --interactive

    # Run without Neptune logging
    python run_custom.py -t targets.json -c config.json --no-neptune
"""

import argparse
import json
import time
import sys
import os
from typing import Optional
from datetime import datetime

import dotenv
dotenv.load_dotenv()

from pentest_agent import PentestAgent
from docker_setup import create_container
from custom_targets.success_criteria import (
    SuccessChecker, parse_criteria, CriteriaType
)

# Optional Neptune import
try:
    import neptune
    import logging
    NEPTUNE_AVAILABLE = True
except ImportError:
    NEPTUNE_AVAILABLE = False


PRINT_SEP = "\n⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯\n"


def load_config(config_path: str) -> dict:
    """Load configuration file"""
    with open(config_path, 'r') as f:
        return json.load(f)


def load_targets(targets_path: str) -> dict:
    """Load targets file"""
    with open(targets_path, 'r') as f:
        return json.load(f)


def init_neptune(config: dict, use_neptune: bool) -> Optional[object]:
    """Initialize Neptune run if enabled"""
    if not use_neptune or not NEPTUNE_AVAILABLE:
        return None
    
    if "neptune" not in config:
        print("[WARNING] Neptune config not found, skipping Neptune logging")
        return None
    
    try:
        run = neptune.init_run(project=config["neptune"]["project"])
        logging.getLogger("neptune").setLevel(logging.ERROR)
        return run
    except Exception as e:
        print(f"[WARNING] Failed to initialize Neptune: {e}")
        return None


def log_to_neptune(run, target_name: str, key: str, value):
    """Log to Neptune if available"""
    if run:
        run[f"targets/{target_name}/{key}"] = value


def log_step_to_neptune(
    run, target_name: str, step: int, max_tries: int,
    summarized_history: str, planner_output: str,
    cmd_to_run: str, command_output: str
):
    """Log step details to Neptune"""
    if run:
        prefix = f"targets/{target_name}"
        run[f"{prefix}/summarized_history"].log(f"[{step+1}/{max_tries}] {summarized_history}")
        run[f"{prefix}/planner_output"].log(f"[{step+1}/{max_tries}] {planner_output}")
        run[f"{prefix}/commands"].log(f"[{step+1}/{max_tries}] {cmd_to_run}")
        run[f"{prefix}/command_outputs"].log(f"[{step+1}/{max_tries}] {command_output}")


def build_target_text(target: dict, config: dict) -> str:
    """Build target description text for the agent"""
    target_template = config.get("target_text", "Target: {target}\nDescription: {description}")
    
    target_text = target_template.format(
        target=target.get("target", ""),
        description=target.get("description", ""),
        info=target.get("description", ""),  # Compatibility with old format
        objective=target.get("objective", target.get("description", ""))
    )
    
    # Add hints if available
    if "hints" in target and target["hints"]:
        target_text += "\n\nHints:\n" + "\n".join(f"- {h}" for h in target["hints"])
    
    # Add file information
    if "files" in target and target["files"]:
        target_text += f"\n\nFiles available: {', '.join(target['files'])}"
    
    return target_text


def run_target(
    target: dict,
    target_name: str,
    config: dict,
    pentest_agent: PentestAgent,
    success_checker: SuccessChecker,
    neptune_run: Optional[object] = None,
    interactive: bool = False,
    verbose: bool = True
) -> tuple[bool, int, dict]:
    """
    Run penetration testing against a single target.
    
    Returns:
        tuple: (success, steps_taken, metrics_dict)
    """
    max_tries = config.get("max_tries", 20)
    
    # Download files if specified
    if "files" in target:
        pentest_agent.download_files(target["files"])
    
    # Build target text
    target_text = build_target_text(target, config)
    
    # Reset agent state
    pentest_agent.reset()
    pentest_agent.target_text = target_text
    
    # Parse success criteria
    if "success_criteria" in target:
        criteria = parse_criteria(target["success_criteria"])
    elif "flag" in target:
        # Backward compatibility with CTF format
        criteria = parse_criteria({
            "type": "contains",
            "value": target["flag"].strip()
        })
    else:
        # Default: manual verification
        criteria = parse_criteria({
            "type": "manual",
            "value": target.get("objective", "Achieve the penetration testing objective")
        })
    
    # Metrics tracking
    t0 = time.time()
    input_tokens = 0
    output_tokens = 0
    command_errors = 0
    succeeded = False
    
    if verbose:
        print(f"\n{'='*50}")
        print(f"Target: {target_name}")
        print(f"Type: {target.get('type', 'custom')}")
        print(f"Objective: {target.get('description', 'N/A')[:100]}")
        print(f"Success Criteria: {criteria.type.value}")
        print(f"Max Tries: {max_tries}")
        print(f"{'='*50}\n")
    
    for step in range(max_tries):
        t0_planner = time.time()
        
        try:
            # Run planner and execute command
            planner_output, cmd_to_run, command_output, p_in_tokens, p_out_tokens = \
                pentest_agent.plan_and_run_cmd(verbose=verbose)
            
            if cmd_to_run == "*No command*":
                command_errors += 1
        except Exception as err:
            print(f"[ERROR] Step {step+1}: {err}")
            command_errors += 1
            continue
        
        planner_time = time.time() - t0_planner
        
        # Run summarizer
        t0_summarizer = time.time()
        summarized_history, s_in_tokens, s_out_tokens = pentest_agent.summarizer(verbose=verbose)
        summarizer_time = time.time() - t0_summarizer
        
        # Check success criteria
        success, msg = success_checker.check(criteria, command_output, summarized_history)
        
        if success:
            succeeded = True
            print(f"\n[SUCCESS] {msg}")
            break
        
        # Update token counts
        input_tokens += p_in_tokens + s_in_tokens
        output_tokens += p_out_tokens + s_out_tokens
        
        # Log to Neptune
        log_step_to_neptune(
            neptune_run, target_name, step, max_tries,
            summarized_history, planner_output, cmd_to_run, command_output
        )
        
        # Interactive mode: allow user to intervene
        if interactive and (step + 1) % 5 == 0:
            print(f"\n[Interactive] Completed {step+1} steps. Continue? [Y/n/success/hint]: ", end="")
            response = input().strip().lower()
            if response == 'n':
                print("Stopped by user")
                break
            elif response == 'success':
                succeeded = True
                print("Manually marked as success")
                break
            elif response == 'hint':
                hint = input("Enter hint for agent: ").strip()
                if hint:
                    pentest_agent.summarized_history += f"\nUser hint: {hint}"
    
    total_time = time.time() - t0
    
    metrics = {
        "success": succeeded,
        "steps": step + 1,
        "total_time": total_time,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "command_errors": command_errors,
        "target_type": target.get("type", "custom"),
        "criteria_type": criteria.type.value
    }
    
    # Log final metrics to Neptune
    if neptune_run:
        for key, value in metrics.items():
            log_to_neptune(neptune_run, target_name, key, value)
    
    return succeeded, step + 1, metrics


def print_summary(results: dict):
    """Print summary of all target results"""
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    
    total = len(results)
    succeeded = sum(1 for r in results.values() if r["success"])
    
    print(f"Total Targets: {total}")
    print(f"Succeeded: {succeeded}")
    print(f"Failed: {total - succeeded}")
    print(f"Success Rate: {succeeded/total*100:.1f}%")
    
    print("\nDetails:")
    print("-"*60)
    for name, r in results.items():
        status = "✓" if r["success"] else "✗"
        print(f"  {status} {name}: {r['steps']} steps, {r['total_time']:.1f}s")
    print("="*60)


def main():
    parser = argparse.ArgumentParser(
        description="HackSynth Custom Target Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('-t', '--targets', required=True,
                        help='Path to targets JSON file')
    parser.add_argument('-c', '--config', required=True,
                        help='Path to config JSON file')
    parser.add_argument('--target', default=None,
                        help='Run specific target by name (optional)')
    parser.add_argument('--no-neptune', action='store_true',
                        help='Disable Neptune logging')
    parser.add_argument('--interactive', '-i', action='store_true',
                        help='Enable interactive mode')
    parser.add_argument('-k', '--keep-running', action='store_true',
                        help="Don't stop the container after exiting")
    parser.add_argument('-v', '--verbose', action='store_true', default=True,
                        help='Verbose output')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Minimal output')
    
    args = parser.parse_args()
    
    verbose = not args.quiet
    
    # Load configuration
    config = load_config(args.config)
    targets = load_targets(args.targets)
    
    if verbose:
        print(f"Loaded config: {args.config}")
        print(f"Loaded {len(targets)} targets from: {args.targets}")
    
    # Filter to specific target if requested
    if args.target:
        if args.target not in targets:
            print(f"[ERROR] Target '{args.target}' not found in targets file")
            print(f"Available targets: {', '.join(targets.keys())}")
            sys.exit(1)
        targets = {args.target: targets[args.target]}
    
    # Initialize Docker container
    container = create_container(config=config)
    
    # Initialize Neptune (optional)
    neptune_run = init_neptune(config, not args.no_neptune)
    
    if neptune_run:
        neptune_run["config.json"].upload(args.config)
        neptune_run["targets.json"].upload(args.targets)
    
    # Initialize agent
    pentest_agent = PentestAgent(
        llm_model_id=config["llm"]["model_id"],
        llm_model_local=config["llm"].get("model_local", False),
        container=container,
        planner_system_prompt=config["planner"]["system_prompt"],
        planner_user_prompt=config["planner"]["user_prompt"],
        summarizer_system_prompt=config["summarizer"]["system_prompt"],
        summarizer_user_prompt=config["summarizer"]["user_prompt"],
        temperature=config["llm"].get("temperature", 0.8),
        top_p=config["llm"].get("top_p", 0.9),
        timeout_duration=config.get("timeout_duration", 10),
        max_new_tokens=config["llm"].get("max_new_tokens", 2500),
        new_observation_length_limit=config.get("new_observation_length_limit", 500),
        prompt_chaining=config["llm"].get("prompt_chaining", False),
        do_sample=config["llm"].get("do_sample", True)
    )
    
    # Initialize success checker
    success_checker = SuccessChecker(
        container=container,
        llm_pipeline=pentest_agent.llm_pipeline
    )
    
    # Run targets
    results = {}
    
    try:
        for target_name, target_data in targets.items():
            target_data["name"] = target_name
            
            success, steps, metrics = run_target(
                target=target_data,
                target_name=target_name,
                config=config,
                pentest_agent=pentest_agent,
                success_checker=success_checker,
                neptune_run=neptune_run,
                interactive=args.interactive,
                verbose=verbose
            )
            
            results[target_name] = metrics
            
            status = "SUCCESS" if success else "FAILED"
            print(f"\n[{status}] {target_name}: {steps} steps" + PRINT_SEP)
    
    except KeyboardInterrupt:
        print("\n[Interrupted by user]")
    
    finally:
        # Print summary
        if results:
            print_summary(results)
        
        # Log final results
        if neptune_run:
            neptune_run["results"] = results
            neptune_run["total_success"] = sum(1 for r in results.values() if r["success"])
            neptune_run["total_targets"] = len(results)
        
        # Cleanup
        if not args.keep_running:
            container.stop()
            if verbose:
                print("Container stopped")
        
        if neptune_run:
            neptune_run.stop()


if __name__ == "__main__":
    main()
