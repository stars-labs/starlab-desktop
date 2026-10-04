# Packaged token identity assets

Downloaded 4 October 2026. Native assets are local so the wallet does not send browsing or address information to an image host.

- SOL: official https://solana.com/src/img/branding/solanaLogoMark.svg ; guidelines https://solana.com/branding . Preserve geometry and gradient.
- BTC: https://github.com/BitcoinDesign/Guide/blob/master/assets/images/guide/getting-started/visual-language/bitcoin-symbol.svg (Bitcoin Design community).
- ETH: https://github.com/spothq/cryptocurrency-icons/tree/master/svg/color (CC0 public-domain icon collection). File geometry retained; these are recognizable marks, not issuer-provided verification badges.
- SUI: https://github.com/trustwallet/assets/blob/master/blockchains/sui/info/logo.png (Trust Wallet asset repository, actual Sui droplet). Primary brand guidance: https://www.sui.io/blog/trademark-usage-reporting .

These native-chain marks use the same packaged image bytes as the Starlab browser extension. Unknown chains receive a neutral icon. The desktop does not infer identity from a token ticker or display an issuer verification badge. No claim of affiliation or endorsement.

Navigation glyphs in `assets.rs` are locally authored stroke SVGs.

`ambient.svg` is locally authored radial-gradient lighting, with no external asset or blur filter.
