"""JSON-RPC bridge for the Finite State Report Server.

Run as: python -m fs_report.bridge

Communicates with the Node.js report server over stdin/stdout using
newline-delimited JSON. Supports listing recipes, running reports with
streaming progress events, and cancellation.
"""
