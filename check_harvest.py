import shutil
import importlib.util
import sys
print("sys.executable:", sys.executable)
print("which theHarvester:", shutil.which("theHarvester"))
print("which theharvester:", shutil.which("theharvester"))
print("find_spec theHarvester:", importlib.util.find_spec('theHarvester'))
print("find_spec theharvester:", importlib.util.find_spec('theharvester'))
