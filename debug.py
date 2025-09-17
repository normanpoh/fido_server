from constants import RP_ID, RP_NAME, ORIGIN, H5_FILE
from fido_utils import FIDOServer, MemoryStorage
from store_var_utils import retrieve_all_namespaces, list_namespaces_df, retrieve_data
import pprint
from typing import cast

df_namespace = list_namespaces_df(H5_FILE)
df_namespace["space"] = df_namespace["namespace"]
df_namespace["date"] = df_namespace["namespace"].str.split("-").str[0]
df_namespace["namespace"] = df_namespace["namespace"].str.split("-").str[1]
df_namespace.sort_values(by="space", inplace=True)


def load_by_date(custom_date: str) -> None:
    """Load and print all namespaces for a given date"""
    # 20250917_222644 or 20250917_2226
    df_date = df_namespace.loc[df_namespace["date"].str.contains(custom_date), :]

    for space in df_date["space"].unique():
        print(space)
        data = retrieve_data(H5_FILE, space)
        if "memory" in space:
            mem_ = MemoryStorage()
            mem_.import_from(cast(str, data["memory"]))
            print(mem_.users)
            print(mem_.user_credentials)
        else:
            print(data)
    return


row = df_namespace.loc[0]
retrieve_data(H5_FILE, row["space"])


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
