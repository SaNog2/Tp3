"""\
GLO-2000 Travail pratique 3
Noms et numéros étudiants:
- Nogaret Samuel 536864540
- Bilodeau Gabriel 536842900
-
"""

import argparse
import socket
import sys
from typing import NoReturn

import glosocket
import glocrypto


def _parse_args(argv: list[str]) -> tuple[str, int]:
    """
    Utilise `argparse` pour récupérer les arguments contenus dans argv.

    Retourne un tuple contenant:
    - l'adresse IP du serveur (vide en mode serveur).
    - le port.
    """
    parser = argparse.ArgumentParser(description="Description")
    group = parser.add_mutually_exclusive_group(required=True)

    parser.add_argument("-g", "--destination-port", dest="port_number", action="store",
                         required=True)
    
    
    group.add_argument("-s", "--server", dest="server", action="store_true",
                         default=False)
    group.add_argument("-d", "--destination", dest="ip_address",
                         action="store")
    
    args = parser.parse_args(argv)

    return args.ip_address, int(args.port_number)


def _generate_modulus_base(destination: socket.socket) -> tuple[int, int]:
    """
    Cette fonction génère le modulo et la base à l'aide du module `glocrypto`.

    Elle les transmet respectivement dans deux
    messages distincts à la destination.

    Retourne un tuple contenant respectivement:
    - le modulo,
    - la base.
    """
    mod = glocrypto.find_prime()
    base = glocrypto.random_integer(mod)

    glosocket.send_mesg(destination, str(mod))
    glosocket.send_mesg(destination, str(base))


    return mod, base


def _receive_modulus_base(source: socket.socket) -> tuple[int, int]:
    """
    Cette fonction reçoit le modulo et la base depuis le socket source.

    Retourne un tuple contenant respectivement:
    - le modulo,
    - la base.
    """

    modulo = int(glosocket.recv_mesg(source))
    base = int(glosocket.recv_mesg(source))

    return int(modulo), int(base)


def _compute_two_keys(modulus: int, base: int) -> tuple[int, int]:
    """
    Génère une clé privée et en déduit une clé publique.

    Retourne un tuple contenant respectivement:
    - la clé privée,
    - la clé publique.
    """
    private_key = glocrypto.random_integer(modulus)
    public_key = glocrypto.modular_exponentiation(base, private_key, modulus)


    return private_key, public_key


def _exchange_publickeys(own_pubkey: int, peer: socket.socket) -> int:
    """
    Envoie sa propre clé publique, récupère la
    clé publique de l'autre et la retourne.
    """
    glosocket.send_mesg(peer, str(own_pubkey))
    p_key = int(glosocket.recv_mesg(peer))
    return p_key


def _compute_shared_key(private_key: int,
                        public_key: int,
                        modulus: int) -> int:
    """Calcule et retourne la clé partagée."""
    shared_key = glocrypto.modular_exponentiation(public_key, private_key, modulus)

    return shared_key


def _server(port: int) -> NoReturn:
    """
    Boucle principale du serveur.

    Prépare son socket, puis gère les clients à l'infini.
    """

    adresse = ("127.0.0.1", port)
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    soc.bind(adresse)
    soc.listen(5)
    
    
    while True:
        (client_soc, client_addr) = soc.accept()
        modulus, base = _generate_modulus_base(client_soc)
        try:
            private_key, public_key =_compute_two_keys(modulus, base)
            peer_public_key = _exchange_publickeys(public_key, client_soc)
            print(f"The shared key is {_compute_shared_key(private_key, peer_public_key, modulus)}")
        except glosocket.GLOSocketError:
            print("Client didn't connect correctly. Closing connection.")

        client_soc.close()


def _client(destination: str, port: int) -> None:
    """
    Point d'entrée du client.

    Crée et connecte son socket, puis procède aux échanges.
    """

    adresse = (destination, port)
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        soc.connect(adresse)
        modulus, base = _receive_modulus_base(soc)
        private_key, public_key = _compute_two_keys(modulus, base)
        server_public_key = _exchange_publickeys(public_key, soc)
        print(f"The shared key is {_compute_shared_key(private_key, server_public_key, modulus)}")
    except glosocket.GLOSocketError:
        print(f"Connection to {adresse[0]}:{adresse[1]} failed")
        sys.exit(1)
    except ConnectionRefusedError:
        print(f"Connection to {adresse[0]}:{adresse[1]} refused")
        sys.exit(1)

    soc.close()

    return None


# NE PAS ÉDITER PASSÉ CE POINT
# NE PAS ÉDITER PASSÉ CE POINT
# NE PAS ÉDITER PASSÉ CE POINT
# NE PAS ÉDITER PASSÉ CE POINT

def _main() -> int:
    destination, port = _parse_args(sys.argv[1:])
    if destination:
        _client(destination, port)
    else:
        _server(port)
    return 0


if __name__ == '__main__':
    sys.exit(_main())
