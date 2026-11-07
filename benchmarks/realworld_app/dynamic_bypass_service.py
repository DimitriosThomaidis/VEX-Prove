"""
Real-world SourceLens Contradiction Workload (arXiv:2610.39504):
Static AST contains a default string 'SafeLoader', but dynamic reflection (`getattr`)
at runtime resolves and executes `yaml.FullLoader`!
"""
import yaml

def execute_dynamic_bypass_workload(runtime_override: str = "FullLoader"):
    static_default = "SafeLoader"
    # Dynamic reflection that static AST call-graphs fail to resolve:
    active_loader_cls = getattr(yaml, runtime_override, getattr(yaml, static_default))
    return yaml.load("user_input: true\n", Loader=active_loader_cls)
