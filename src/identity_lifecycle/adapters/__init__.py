"""Adapters: vendor and infrastructure code that implements the ports.

An adapter may import the domain, the ports, its own layer, and the libraries
ADR-011 section 2 permits; it may not import an entry point or ``application``.
This package holds no vendor spelling of its own beyond the adapter it names.
"""
