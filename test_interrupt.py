#!/usr/bin/env python3
"""
Test script to verify that Ctrl+C interrupt handling works properly.
This script simulates a scan that can be interrupted gracefully.
"""

import sys
import os
import signal
import threading
import time

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from console import signal_handler, interrupt_flag

def simulate_long_running_task():
    """Simulate a long-running task that checks for interrupts."""
    print("🚀 Starting simulated scan...")
    print("💡 Press Ctrl+C to test interrupt handling")
    
    for i in range(100):
        if interrupt_flag.is_set():
            print(f"\n🛑 Task interrupted at iteration {i}")
            return False
            
        print(f"\r⏳ Processing item {i+1}/100...", end='', flush=True)
        time.sleep(0.1)  # Simulate work
    
    print(f"\n✅ Task completed successfully!")
    return True

def main():
    """Test the interrupt handling."""
    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("🧪 Testing Interrupt Handling")
    print("=" * 40)
    
    try:
        completed = simulate_long_running_task()
        
        if completed:
            print("📊 Result: Task completed without interruption")
        else:
            print("📊 Result: Task was interrupted gracefully")
            
    except KeyboardInterrupt:
        print("\n⚠️  Caught KeyboardInterrupt (backup handler)")
        interrupt_flag.set()
    
    print(f"🏁 Test finished. Interrupt flag set: {interrupt_flag.is_set()}")

if __name__ == "__main__":
    main()
