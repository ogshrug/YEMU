import colorsys

import pytest

pytest.importorskip("PySide6.QtWidgets")

from yemu.gui import theme  # noqa: E402

PALETTES = {"light": theme.LIGHT, "dark": theme.DARK}

# (foreground, background) pairs that carry text or meaning and must reach WCAG AA (4.5:1)
PAIRS = [
    ("text", "bg"),
    ("text", "surface"),
    ("text", "surface_alt"),
    ("muted", "bg"),
    ("muted", "surface"),
    ("accent_text", "accent"),
    ("sidebar_text", "sidebar"),
    ("accent", "surface"),
    ("danger", "surface"),
    ("warn", "surface"),
    ("ok", "surface"),
]


def _rgb(hex_color):
    h = hex_color.lstrip("#")
    return tuple(int(h[i : i + 2], 16) / 255 for i in (0, 2, 4))


def _luminance(hex_color):
    def channel(v):
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4

    r, g, b = (channel(v) for v in _rgb(hex_color))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _contrast(a, b):
    hi, lo = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def test_palettes_have_the_same_tokens():
    assert theme.LIGHT.keys() == theme.DARK.keys()


@pytest.mark.parametrize("name", PALETTES)
@pytest.mark.parametrize("fg,bg", PAIRS)
def test_palette_contrast_meets_wcag_aa(name, fg, bg):
    c = PALETTES[name]
    assert _contrast(c[fg], c[bg]) >= 4.5, f"{name}: {fg} on {bg}"


@pytest.mark.parametrize("name", PALETTES)
def test_accent_is_not_indigo_or_violet(name):
    hue, _, _ = colorsys.rgb_to_hls(*_rgb(PALETTES[name]["accent"]))
    assert not 220 <= hue * 360 <= 300
