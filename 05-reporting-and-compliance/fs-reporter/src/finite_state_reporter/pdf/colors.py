"""
Professional color palette for Finite State PDF reports.
Based on the platform's color scheme with brand-consistent colors.
"""

from reportlab.lib.colors import HexColor, blue, gray, white, whitesmoke  # noqa: F401

# Brand Colors
darkjunglegreen = HexColor(0x1F2D3D)
lightblue = HexColor(0x446DBB)
lightskyblue = HexColor(0x90CAF9)
pictonblue = HexColor(0x42A5F5)
bluedress = HexColor(0x1E88E5)
blueeyes = HexColor(0x1565C0)

# Blue Palette
blue200 = lightskyblue
blue400 = pictonblue
blue600 = bluedress
blue800 = blueeyes
muted = HexColor(0xC6DAF7)

# Accent Colors
coral = HexColor(0xF67D39)
midnightblue = HexColor(0x0C0E40)
mystic = HexColor(0xE3E8EF)
brightgray = mystic
arsenic = HexColor(0x424242)

# Grayscale
gray100 = whitesmoke
grey800 = arsenic
whitesmoke = HexColor(0xF1F5F9)
charcoal = HexColor(0x344155)

# Status Colors
chestnutred = HexColor(0xC75037)
dustyorange = HexColor(0xF67D39)
sandstorm = HexColor(0xEECF50)
silkblue = HexColor(0x4C82D6)
mutedpurple = HexColor(0x8F91A6)
midgray = HexColor(0xE1E1E1)

# Severity Colors (for vulnerability reports)
CRITICAL_COLOR = chestnutred
HIGH_COLOR = dustyorange
MEDIUM_COLOR = sandstorm
LOW_COLOR = silkblue
UNKNOWN_COLOR = mutedpurple


def hashhex(color):
    """Convert color to hex string format for external libraries."""
    return f"#{color.hexval()[2:]}"


# Severity color mapping
SEVERITY_COLORS = {
    "Critical": CRITICAL_COLOR,
    "High": HIGH_COLOR,
    "Medium": MEDIUM_COLOR,
    "Low": LOW_COLOR,
    "None": midgray,  # Use gray for 'None' severity
    "Unknown": UNKNOWN_COLOR,
}

# Component type color mapping
COMPONENT_COLORS = {
    "library": lightblue,
    "operating-system": darkjunglegreen,
    "firmware": coral,
    "file": midnightblue,
    "application": dustyorange,
    "container": mutedpurple,
    "package": sandstorm,
    "unknown": midgray,
}
