#!/bin/bash
rm -f *.bin
python3 key_management_tool.py cancel_key_manifest0_keys.config
python3 key_management_tool.py cancel_key_manifest1_keys.config
