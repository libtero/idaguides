# IDA Guides

Small plugin for IDA that adds indent guides to the decompiler view.

![preview](preview.png)


## Installation

1. Clone or download this repository
2. Extract it's contents to your IDA `plugins` directory
3. Restart IDA


## Tested With

- IDA 9.2


## Notes

The plugin reads the indent level from `hexrays.cfg` (default: 2) and reapplies it on load. Changing the decompiler’s indent setting afterward will cause guides to display incorrectly.
