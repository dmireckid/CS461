#!/usr/bin/python
# -*- coding: utf-8 -*-
blob = """          1�U��"ZE��6L���U@Z�hޅa*yn$&�����	����u</8�+4�\��4i��&��G $tk�Z^᭷qd�E���v�[�5x����"�Iz�%]���j����mb�
FU�"""
from hashlib import sha256
if (str(sha256(blob).hexdigest()) == 'c8762b670291c21c11175b4e1eac7e001ae7f4c03fe392a3b5ad7566a6901910'):
	print "I come in peace."
else:
	print "Prepare to be destroyed!"