/* Vault100 web — Annex D instruments script. */
"use strict";

(() => {
  const { $, log, sendJob, download, addResult, estimateStrength } = window.VB;

  // (a) the keyfile press
  $("#keygen-go").onclick = () => {
    const bytes = new Uint8Array(8 + 32);
    bytes.set(new TextEncoder().encode("V100KEY1"), 0);
    crypto.getRandomValues(bytes.subarray(8));
    const saved = download("vault100-" +
      Date.now().toString(36) + ".v100key", [bytes], bytes.length);
    addResult(saved.name, saved.size);
    log("Keyfile created — store it like a house key, and back it up.");
  };

  // (b) the examining glass
  $("#info-pick-btn").onclick = () => $("#info-pick").click();
  $("#info-pick").onchange = async (e) => {
    const f = e.target.files[0];
    e.target.value = "";
    if (!f) return;
    const info = await sendJob({ op: "info", file: f });
    if (!info || !info.format) return log("Could not parse vault header.", "err");
    log(`🔍 ${info.name}: v${info.format} · ` +
      `cipher ${info.cascade ? "AES-256-GCM⟶XChaCha20" : "XChaCha20-Poly1305"} · ` +
      `keyfile ${info.keyfile ? "required" : "no"} · ` +
      `Argon2id ${Math.round(info.kdf.memoryKib / 1024)} MiB×${info.kdf.timeCost}`);
  };

  // (c) the passphrase press
  const WORDS = ("amber anvil apple arrow aspen atlas aurora bacon badge bamboo banjo " +
    "barn basin bazaar beacon beaver berry birch biscuit blaze blender blossom bonsai " +
    "border boulder breeze brick bridge bronze brook bubble bucket butter button cactus " +
    "camel canoe canyon caramel castle cedar cellar cello chalk charcoal cherry chest " +
    "chimney cider cinder circuit citrus clover cobalt cocoa comet compass copper coral " +
    "crater cricket crystal cypress dagger daisy dawn delta denim desert dew diamond " +
    "dolphin dome donkey dragon drift drum dune eagle echo ember emerald engine falcon " +
    "feather fern fiddle flint forge fossil fountain fox frost galaxy garden garnet gate " +
    "gecko glacier gondola granite gravel grove guitar harbor harvest hazel hedge heron " +
    "honey horizon hotel hunter iceberg igloo indigo iron island ivory jade jaguar jasmine " +
    "jester jet jewel jungle juniper kayak kestrel kettle kingdom kite kitten ladder " +
    "lagoon lantern lark lava lemon leopard lily linen lion lizard lobster lodge lotus " +
    "lunar magnet mahogany mango maple marble marlin meadow mesa meteor midnight mill " +
    "mirror mist molten monsoon moss moth mountain mulberry mustard nectar needle nickel " +
    "north oasis obsidian ocean olive onyx opal orbit orchid otter owl oyster panda " +
    "panther paper parrot pearl pebble pelican pepper petal phoenix piano pilgrim pine " +
    "pioneer planet plum polar poppy prairie prism python quartz quill rabbit rain raven " +
    "reef rhino river robin rocket root rose ruby saddle safari sage salmon sand sapphire " +
    "satin savanna scarlet seashell sequoia shadow shale shard silver skylark slate smoke " +
    "snow solar sparrow sphinx spider spirit spring spruce stable star stone storm summit " +
    "sunrise sunset swallow tango temple thunder tidal tiger timber titan topaz torch " +
    "tornado trader trident tropic tulip tundra tunnel turquoise turtle twilight umber " +
    "unicorn valley vapor velvet vine violet viper vortex voyage walnut wanderer wasp " +
    "wave weasel west whale wheat whisper willow winter wolf wren yellow zenith zephyr " +
    "zinc zodiac").split(" ");
  function randInt(max) {
    const b = new Uint32Array(1);
    crypto.getRandomValues(b);
    return b[0] % max;
  }
  $("#genpass-go").onclick = () => {
    const phrase = $("#genpass-words").checked;
    let pw;
    if (phrase) {
      const parts = [];
      for (let i = 0; i < 8; i++) parts.push(WORDS[randInt(WORDS.length)]);
      pw = parts.join("-");
    } else {
      const A = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.<>?/~";
      pw = Array.from({ length: 20 }, () => A[randInt(A.length)]).join("");
    }
    $("#genpass-out").value = pw;
    const r = estimateStrength(pw);
    $("#genpass-strength").textContent = r.label;
  };
  $("#genpass-copy").onclick = async () => {
    await navigator.clipboard.writeText($("#genpass-out").value);
    log("Password copied to clipboard.");
  };
})();
