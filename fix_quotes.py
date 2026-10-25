#!/usr/bin/env python3
# Corregir comillas escapadas en HunterBugGUI.py
with open('HunterBugGUI.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Reemplazar \ + " con "
content = content.replace('\\"', '"')

with open('HunterBugGUI.py', 'w', encoding='utf-8') as f:
    f.write(content)

# Verificar
with open('HunterBugGUI.py', 'r', encoding='utf-8') as f:
    content = f.read()

import ast
try:
    ast.parse(content)
    print('Sintaxis OK')
except SyntaxError as e:
    print(f'Sintaxis error: {e}')
