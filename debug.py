from constants import RP_ID, RP_NAME, ORIGIN, H5_FILE
from fido_utils import FIDOServer, MemoryStorage
from store_var_utils import retrieve_all_namespaces
import pprint
from typing import cast

memory = retrieve_all_namespaces(H5_FILE)
print(memory.keys())

# var_ = memory["attestation_result_response"]
mem_ = MemoryStorage()
mem_.import_from(cast(str, memory["memory"]["memory"]))
fido_server = FIDOServer(RP_ID, RP_NAME, ORIGIN, memory_storage=mem_)
self = fido_server

# Case 1: complete registration
# pprint.pprint(memory["attestation_result"])
# mem = memory["attestation_result"]
# cred = CredentialData(**mem["credential_data"])
# result = fido_server.complete_registration(credential_data=cred, session=mem["session"])


# Case 2:
pprint.pprint(memory["assertion_options"])

res = fido_server.start_authentication(
    username=memory["assertion_options"]["request"]["username"],
    session=memory["assertion_options"]["session"],
)
pprint.pprint(res)

memory["assertion_options_response"]
memory["assertion_result"].keys()

# cred = CredentialData(**credential_data)
# result = fido_server.complete_authentication(cred, session)
# result = fido_server.complete_registration(credential_data=cred, session=mem["session"])
