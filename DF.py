from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization # Certifique-se desta importação

# Gerar os parâmetros DH
parameters = dh.generate_parameters(generator=2, key_size=1024, backend=default_backend())

pem_parameters = parameters.parameter_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.ParameterFormat.PKCS3
)

with open("dh_params.pem", "wb") as f:
    f.write(pem_parameters)

print("Parâmetros DH gerados e salvos em dh_params.pem. Copie este conteúdo para seus scripts.")
print("\n--- Conteúdo dos parâmetros (para copiar) ---")
print(pem_parameters.decode())
print("---------------------------------------------")
