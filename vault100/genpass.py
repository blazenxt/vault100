"""Cryptographically secure password / passphrase generator.

Uses `secrets` (OS CSPRNG) only. Word passphrase entropy:
~8.5 bits/word (400-word list) → 8 words ≈ 68 bits; combined with
Argon2id that is centuries of offline-guessing time. Random mode draws
from a 90-symbol alphabet (~6.5 bits/char).
"""

from __future__ import annotations

import secrets

_WORDS = (
    "amber anvil apple arrow aspen atlas aurora bacon badge bamboo banjo "
    "barn basin bazaar beacon beaver berry birch biscuit blaze blender "
    "blossom bonsai border boulder breeze brick bridge bronze brook bubble "
    "bucket butter button cactus caldera camel canoe canyon caramel carbon "
    "castle cedar cellar cello chalk charcoal cherry chest chimney cider "
    "cinder circuit citrus clover cobalt cocoa comet compass copper coral "
    "crater cricket crystal cypress dagger daisy dawn delta denim desert "
    "dew diamond dolphin dome donkey dragon drift drum dune eagle echo "
    "ember emerald engine falcon feather fern fiddle flint forge fossil "
    "fountain fox frost galaxy garden garnet gate gecko glacier gondola "
    "granite gravel grove guitar gutter harbor harvest hazel hedge heron "
    "honey horizon hotel hunter iceberg igloo indigo iron island ivory jade "
    "jaguar jasmine jester jet jewel jungle juniper kayak kestrel kettle "
    "kingdom kite kitten ladder lagoon lantern lark lava lemon leopard "
    "lily linen lion lizard lobster lodge lotus lunar magnet mahogany "
    "mango maple marble marlin meadow mesa meteor midnight mill mirror "
    "mist molten monsoon moss moth mountain mulberry mustard nectar needle "
    "nickel north oasis obsidian ocean olive onyx opal orbit orchid otter "
    "owl oyster panda panther paper parrot pearl pebble pelican pepper "
    "petal phoenix piano pilgrim pine pioneer planet plum polar poppy "
    "prairie prism python quartz quill rabbit rain raven reef rhino river "
    "robin rocket root rose ruby saddle safari sage salmon sand sapphire "
    "satin savanna scarlet seashell sequoia shadow shale shard silver "
    "skylark slate smoke snow solar sparrow sphinx spider spirit spring "
    "spruce stable star stone storm summit sunrise sunset swallow tango "
    "temple thunder tidal tiger timber titan topaz torch tornado trader "
    "trident tropic tulip tundra tunnel turquoise turtle twilight umber "
    "unicorn valley vapor velvet vine violet viper vortex voyage walnut "
    "wanderer wasp wave weasel west whale wheat whisper willow winter "
    "wolf wren yellow zenith zephyr zinc zodiac"
).split()

_ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/~"


def gen_passphrase(words: int = 8, separator: str = "-") -> str:
    """Diceware-style passphrase from the local word list."""
    if not 4 <= words <= 20:
        raise ValueError("words must be between 4 and 20")
    return separator.join(secrets.choice(_WORDS) for _ in range(words))


def gen_password(length: int = 20, *, symbols: bool = True) -> str:
    """Random password with guaranteed class coverage."""
    if not 8 <= length <= 256:
        raise ValueError("length must be between 8 and 256")
    alphabet = _ALNUM + (_SYMBOLS if symbols else "")
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        has = (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
               and any(c.isdigit() for c in pw)
               and (not symbols or any(c in _SYMBOLS for c in pw)))
        if has:
            return pw
