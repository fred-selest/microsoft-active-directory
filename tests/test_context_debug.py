"""
Debug context processor variables
"""
from core.context_processor import inject_globals

result = inject_globals()

print("Context processor variables:")
print(f"  menu_items: {len(result.get('menu_items', []))} items")
print(f"  tool_items: {len(result.get('tool_items', []))} items")
print(f"  admin_items: {len(result.get('admin_items', []))} items")
print(f"  has_permission: {result.get('has_permission')}")

# Test permission
has_perm = result.get('has_permission')
if has_perm:
    print(f"\nPermission tests:")
    print(f"  has_permission('admin'): {has_perm('admin')}")
    print(f"  has_permission('read'): {has_perm('read')}")
    print(f"  has_permission('write'): {has_perm('write')}")

print(f"\nTool items:")
for item in result.get('tool_items', []):
    print(f"  - {item}")

print(f"\nAdmin items:")
for item in result.get('admin_items', []):
    print(f"  - {item}")
