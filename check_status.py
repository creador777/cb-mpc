import sys, json, subprocess, math
sys.path.insert(0, 'problems/seismic-damper/scorer')
import compute_score as cs

checks = []
total = 6

oracle = [980.0, 900.0, 820.0, 660.0, 500.0, 390.0]
d = cs.compute_peak_drift(oracle)
s, m = cs.compute_score(oracle, d)
ok = s >= 1.0
checks.append(ok)
print(f"CHECK 1 - Oracle score 1.0: {'PASS' if ok else 'FAIL'} (score={s})")

naive = [800.0]*6
d2 = cs.compute_peak_drift(naive)
s2, m2 = cs.compute_score(naive, d2)
ok = s2 < 0.5
checks.append(ok)
print(f"CHECK 2 - Naive score < 0.5: {'PASS' if ok else 'FAIL'} (score={s2})")

big = [1500.0, 1400.0, 1200.0, 1000.0, 800.0, 600.0]
d3 = cs.compute_peak_drift(big)
s3, m3 = cs.compute_score(big, d3)
ok = s3 == 0.0
checks.append(ok)
print(f"CHECK 3 - Budget fail = 0.0: {'PASS' if ok else 'FAIL'}")

zero = [0.0]*6
d4 = cs.compute_peak_drift(zero)
s4, m4 = cs.compute_score(zero, d4)
ok = s4 == 0.0
checks.append(ok)
print(f"CHECK 4 - Zero damp fail = 0.0: {'PASS' if ok else 'FAIL'}")

result = subprocess.run(['python3', '-m', 'pytest', 'problems/seismic-damper/tests/test_scorer_contract.py', '-q'], capture_output=True, text=True)
ok = result.returncode == 0
checks.append(ok)
print(f"CHECK 5 - Tests pass: {'PASS' if ok else 'FAIL'} ({result.stdout.strip()})")

inst = open('problems/seismic-damper/instruction.md').read().lower()
bad_words = ['opensees', 'openseespy', 'compute_score', 'scorer', 'python']
inst_ok = all(w not in inst for w in bad_words)
checks.append(inst_ok)
print(f"CHECK 6 - Instruction is agnostic: {'PASS' if inst_ok else 'FAIL'}")

passed = sum(1 for c in checks if c)
print(f"\nRESULT: {passed}/{total} checks PASSED")
if all(checks):
    print("TAREA 100% LISTA PARA ENTREGAR!")
else:
    print(f"FALTAN {total-passed} CHECK(S)")

