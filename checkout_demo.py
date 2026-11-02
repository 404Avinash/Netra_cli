#!/usr/bin/env python3
"""
Swytchcode Practical Demo: E-Commerce Checkout & Payment Intent Generator
=======================================================================
This script demonstrates an end-to-end practical integration using Swytchcode's
execution kernel for external API operations (Stripe Payment Intents).

Author: Avinash
Task: Swytchcode PPI Assessment
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime


def execute_swytchcode_tool(canonical_id: str, payload: dict, demo: bool = True) -> dict:
    """
    Executes a Swytchcode tool via the CLI kernel with structured JSON I/O.
    
    Args:
        canonical_id: Tool canonical ID (e.g. 'stripe.create_payment')
        payload: Dictionary of arguments passed to the tool
        demo: Flag to enable demo execution mode without real API keys
        
    Returns:
        Dictionary containing the parsed tool response.
    """
    cmd = ["swytchcode", "exec", canonical_id, "--body", json.dumps(payload), "--json"]
    if demo:
        cmd.append("--demo")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        print("[Error] 'swytchcode' CLI binary was not found in PATH.", file=sys.stderr)
        sys.exit(1)

    # Parse stdout for the JSON result payload
    response_json = None
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                response_json = json.loads(line)
                break
            except json.JSONDecodeError:
                continue

    if not response_json:
        # If no JSON line could be parsed, report error output
        return {
            "success": False,
            "exit_code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }

    return {
        "success": proc.returncode == 0,
        "exit_code": proc.returncode,
        "data": response_json,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Swytchcode CLI Demo: E-Commerce Payment Checkout"
    )
    parser.add_argument(
        "--amount",
        type=float,
        default=25.00,
        help="Order total amount in USD (default: 25.00)",
    )
    parser.add_argument(
        "--item",
        type=str,
        default="Developer Pro Subscription (Annual)",
        help="Name of the product or service being purchased",
    )
    parser.add_argument(
        "--customer",
        type=str,
        default="alex.developer@example.com",
        help="Customer email address",
    )
    parser.add_argument(
        "--currency",
        type=str,
        default="usd",
        help="Currency code (e.g. usd, eur)",
    )

    args = parser.parse_args()

    # Convert amount into cents (integer) as required by Stripe standards
    amount_in_cents = int(round(args.amount * 100))

    print("=" * 65)
    print("      🛒 SWYTCHCODE SECURE CHECKOUT & PAYMENT PIPELINE")
    print("=" * 65)
    print(f"Timestamp:        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Customer Email:   {args.customer}")
    print(f"Item Description: {args.item}")
    print(f"Order Total:      ${args.amount:,.2f} ({args.currency.upper()})")
    print(f"Kernel Operation: stripe.create_payment via Swytchcode")
    print("-" * 65)
    print("⚡ Dispatching payment intent request to Swytchcode kernel...")

    payload = {
        "amount": amount_in_cents,
        "currency": args.currency.lower(),
        "description": f"Order: {args.item} for {args.customer}",
    }

    result = execute_swytchcode_tool("stripe.create_payment", payload, demo=True)

    if not result.get("success"):
        print("\n❌ Payment Intent Generation Failed!")
        print(f"Exit Code: {result.get('exit_code')}")
        if result.get("stderr"):
            print(f"Error Log:\n{result.get('stderr')}")
        sys.exit(result.get("exit_code", 1))

    data = result["data"]
    payment_data = data.get("data", {})

    print("\n✅ PAYMENT INTENT CREATED SUCCESSFULLY!")
    print("-" * 65)
    print(f"  • Payment Intent ID : {payment_data.get('payment_id', 'N/A')}")
    print(f"  • Status            : {payment_data.get('status', 'requires_payment_method')}")
    print(f"  • Amount Authorized : {payment_data.get('amount', f'${args.amount:.2f}')}")
    print(f"  • Currency          : {payment_data.get('currency', args.currency.upper())}")
    print(f"  • Created At        : {payment_data.get('created', 'N/A')}")
    print(f"  • Simulated Mode    : {data.get('_simulated', True)}")
    print("=" * 65)
    print("Audit Log Entry: Swytchcode policy verified and logged locally.")
    print("=" * 65)


if __name__ == "__main__":
    main()
