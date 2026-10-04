// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Declarative themes.
//!
//! v1 item 6 of the definition-of-done: theme support with **no code**
//! (madde 4). A theme is a JSON document of colours, type and spacing, and
//! this module turns one into a flat set of resolved tokens that an interface
//! consumes.
//!
//! ## "No code" has to be structural, not a promise
//!
//! A theme format that accepts arbitrary keys with arbitrary values is a
//! scripting surface waiting for someone to notice. So:
//!
//! * **Every key is known.** An unrecognised one is an error, not an extension
//!   point. There is nowhere to put something a reader would skip over.
//! * **Every value is a constrained type** — a colour, a bounded number, an
//!   enumerated word. Not a string that something later interprets.
//! * **Font families are names, not sources.** `url(...)`, `;`, braces and
//!   `@import` are refused, because the interface will eventually interpolate
//!   this into a stylesheet and that is where a theme would otherwise become
//!   CSS injection. Refusing it here, before any such interface exists, is
//!   cheaper than remembering to escape it later.
//! * **No remote references at all.** Nothing in a theme causes a network
//!   request, so installing one cannot tell anybody that you did.
//!
//! ## Why contrast checking lives here
//!
//! Basic accessibility is a v1 exit criterion (madde 35), and a theme is the
//! most likely way to break it: a user-installed palette can make text
//! unreadable with no code involved at all. [`ResolvedTheme::contrast_report`]
//! computes the WCAG 2.1 ratios for the pairs that actually get rendered, so
//! this is checkable from a command line before any window exists — which is
//! the only reason it is checkable at all right now.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Schema version of the theme document this build reads.
pub const THEME_SCHEMA_VERSION: u32 = 0;

/// Which built-in palette fills in what a theme does not specify.
///
/// A theme states this rather than being guessed at: a theme that sets only an
/// accent colour needs to say whether the rest should come out dark or light,
/// and inferring it from the one colour given is the kind of cleverness that
/// produces black text on a black background.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThemeBase {
    /// Light text on a dark ground.
    Dark,
    /// Dark text on a light ground.
    Light,
}

/// A colour role an interface can ask for.
///
/// A closed set, which is what makes a theme portable: an interface knows
/// every token it can be handed, and a theme knows every token it can set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ColorToken {
    /// The window's ground.
    Background,
    /// A raised panel.
    Surface,
    /// A second raised level, for rows and wells.
    SurfaceVariant,
    /// Primary text.
    Text,
    /// Secondary text: captions, metadata.
    TextMuted,
    /// The accent, for selection and primary actions.
    Accent,
    /// Text drawn on top of the accent.
    AccentText,
    /// Hairlines and separators.
    Border,
    /// Error state.
    Danger,
    /// Text drawn on top of an error state.
    DangerText,
    /// Warning state.
    Warning,
    /// Success state.
    Success,
    /// The focus ring. Separate from the accent because a focus indicator has
    /// its own contrast requirement.
    Focus,
}

impl ColorToken {
    /// Every token, so a resolved theme can be complete by construction.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Background,
            Self::Surface,
            Self::SurfaceVariant,
            Self::Text,
            Self::TextMuted,
            Self::Accent,
            Self::AccentText,
            Self::Border,
            Self::Danger,
            Self::DangerText,
            Self::Warning,
            Self::Success,
            Self::Focus,
        ]
    }

    /// The token name as it appears in a document and in resolved output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Background => "background",
            Self::Surface => "surface",
            Self::SurfaceVariant => "surfaceVariant",
            Self::Text => "text",
            Self::TextMuted => "textMuted",
            Self::Accent => "accent",
            Self::AccentText => "accentText",
            Self::Border => "border",
            Self::Danger => "danger",
            Self::DangerText => "dangerText",
            Self::Warning => "warning",
            Self::Success => "success",
            Self::Focus => "focus",
        }
    }
}

/// An sRGB colour with an alpha channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Color {
    /// Red, 0-255.
    pub r: u8,
    /// Green, 0-255.
    pub g: u8,
    /// Blue, 0-255.
    pub b: u8,
    /// Alpha, 0-255. 255 is opaque.
    pub a: u8,
}

impl Color {
    /// An opaque colour.
    #[must_use]
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }

    /// Parse `#rgb`, `#rgba`, `#rrggbb` or `#rrggbbaa`.
    ///
    /// Hex only. Named colours and `rgb()` notation are deliberately absent:
    /// one spelling per colour keeps a theme document comparable with itself,
    /// and a named-colour table is a hundred and forty opinions nobody asked
    /// this project to hold.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidTheme`] with what is wrong about it.
    pub fn parse(text: &str) -> Result<Self> {
        let bad = || {
            Error::InvalidTheme(format!(
                "'{text}' is not a colour; write #rgb, #rgba, #rrggbb or #rrggbbaa"
            ))
        };
        let hex = text.strip_prefix('#').ok_or_else(bad)?;
        if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(bad());
        }
        let nibble = |index: usize| -> Result<u8> {
            u8::from_str_radix(&hex[index..=index], 16).map_err(|_| bad())
        };
        let byte = |index: usize| -> Result<u8> {
            u8::from_str_radix(&hex[index..index + 2], 16).map_err(|_| bad())
        };
        match hex.len() {
            3 => Ok(Self {
                r: nibble(0)? * 17,
                g: nibble(1)? * 17,
                b: nibble(2)? * 17,
                a: 255,
            }),
            4 => Ok(Self {
                r: nibble(0)? * 17,
                g: nibble(1)? * 17,
                b: nibble(2)? * 17,
                a: nibble(3)? * 17,
            }),
            6 => Ok(Self {
                r: byte(0)?,
                g: byte(2)?,
                b: byte(4)?,
                a: 255,
            }),
            8 => Ok(Self {
                r: byte(0)?,
                g: byte(2)?,
                b: byte(4)?,
                a: byte(6)?,
            }),
            _ => Err(bad()),
        }
    }

    /// Render as `#rrggbb`, or `#rrggbbaa` when it is not opaque.
    ///
    /// Always the long form, so resolved output has one spelling per colour
    /// whatever the document used.
    #[must_use]
    pub fn to_hex(self) -> String {
        if self.a == 255 {
            format!("#{:02x}{:02x}{:02x}", self.r, self.g, self.b)
        } else {
            format!("#{:02x}{:02x}{:02x}{:02x}", self.r, self.g, self.b, self.a)
        }
    }

    /// Composite this colour over an opaque backdrop.
    ///
    /// Needed before any contrast calculation: the ratio for semi-transparent
    /// text is the ratio of what the eye actually sees, and treating `#fff8`
    /// as white would report a passing contrast for text that is in fact grey.
    #[must_use]
    pub fn over(self, backdrop: Self) -> Self {
        if self.a == 255 {
            return self;
        }
        let alpha = f64::from(self.a) / 255.0;
        let mix = |top: u8, bottom: u8| -> u8 {
            let value = f64::from(top).mul_add(alpha, f64::from(bottom) * (1.0 - alpha));
            // Clamped into range before the cast, which is what makes the
            // truncation and sign loss the lint warns about unreachable: both
            // inputs are `u8` and `alpha` is within 0..=1, so the result is
            // already inside 0..=255 and the clamp only pins the rounding.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let byte = value.round().clamp(0.0, 255.0) as u8;
            byte
        };
        Self {
            r: mix(self.r, backdrop.r),
            g: mix(self.g, backdrop.g),
            b: mix(self.b, backdrop.b),
            a: 255,
        }
    }

    /// WCAG 2.1 relative luminance.
    #[must_use]
    pub fn relative_luminance(self) -> f64 {
        let channel = |value: u8| -> f64 {
            let srgb = f64::from(value) / 255.0;
            if srgb <= 0.040_45 {
                srgb / 12.92
            } else {
                ((srgb + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126f64.mul_add(
            channel(self.r),
            0.7152f64.mul_add(channel(self.g), 0.0722 * channel(self.b)),
        )
    }

    /// WCAG 2.1 contrast ratio against `other`, between 1.0 and 21.0.
    ///
    /// Both colours are composited over `backdrop` first, so a translucent
    /// value is measured as rendered rather than as written.
    #[must_use]
    pub fn contrast_ratio(self, other: Self, backdrop: Self) -> f64 {
        let a = self.over(backdrop).relative_luminance();
        let b = other.over(backdrop).relative_luminance();
        let (lighter, darker) = if a >= b { (a, b) } else { (b, a) };
        (lighter + 0.05) / (darker + 0.05)
    }
}

impl Serialize for Color {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Color {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// Type choices.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Typography {
    /// Preferred sans-serif family name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sans: Option<String>,
    /// Preferred monospace family name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mono: Option<String>,
    /// Base size in CSS pixels. Bounded, because a theme that sets 2px text
    /// is an accessibility failure however it was meant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_size: Option<f64>,
    /// Ratio between steps of the type scale.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scale: Option<f64>,
}

/// Corner rounding, in CSS pixels.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Radius {
    /// Controls and inputs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub small: Option<u32>,
    /// Cards and panels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub medium: Option<u32>,
    /// Dialogs and sheets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub large: Option<u32>,
}

/// Layout rhythm.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spacing {
    /// The base spacing unit in CSS pixels; every gap is a multiple of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<u32>,
}

/// A theme document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ThemeDocument {
    /// Schema version of this document.
    pub schema_version: u32,
    /// Which built-in palette fills in the rest.
    pub base: ThemeBase,
    /// Colour overrides.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub colors: BTreeMap<ColorToken, Color>,
    /// Type overrides.
    #[serde(default)]
    pub typography: Typography,
    /// Corner rounding overrides.
    #[serde(default)]
    pub radius: Radius,
    /// Spacing overrides.
    #[serde(default)]
    pub spacing: Spacing,
}

impl ThemeDocument {
    /// Parse and validate a theme document.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedJson`] if the bytes are not the JSON this schema
    /// describes — an unknown key included — or [`Error::InvalidTheme`] if it
    /// parses but is not usable.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let document: Self = serde_json::from_slice(bytes).map_err(|e| Error::MalformedJson {
            message: e.to_string(),
        })?;
        document.validate()?;
        Ok(document)
    }

    /// A theme that changes nothing about `base`.
    #[must_use]
    pub fn plain(base: ThemeBase) -> Self {
        Self {
            schema_version: THEME_SCHEMA_VERSION,
            base,
            colors: BTreeMap::new(),
            typography: Typography::default(),
            radius: Radius::default(),
            spacing: Spacing::default(),
        }
    }

    /// Check everything the types cannot.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidTheme`] with what is wrong.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != THEME_SCHEMA_VERSION {
            return Err(Error::InvalidTheme(format!(
                "schemaVersion is {}, this build reads {THEME_SCHEMA_VERSION}",
                self.schema_version
            )));
        }
        for family in [&self.typography.sans, &self.typography.mono]
            .into_iter()
            .flatten()
        {
            validate_font_family(family)?;
        }
        if let Some(size) = self.typography.base_size {
            if !(10.0..=32.0).contains(&size) {
                return Err(Error::InvalidTheme(format!(
                    "typography.baseSize {size} is outside 10-32px; smaller than 10px \
                     is unreadable and larger breaks every layout"
                )));
            }
        }
        if let Some(scale) = self.typography.scale {
            if !(1.05..=2.0).contains(&scale) {
                return Err(Error::InvalidTheme(format!(
                    "typography.scale {scale} is outside 1.05-2.0"
                )));
            }
        }
        for (name, value) in [
            ("radius.small", self.radius.small),
            ("radius.medium", self.radius.medium),
            ("radius.large", self.radius.large),
        ] {
            if let Some(value) = value {
                if value > 64 {
                    return Err(Error::InvalidTheme(format!("{name} {value} exceeds 64px")));
                }
            }
        }
        if let Some(unit) = self.spacing.unit {
            if !(2..=16).contains(&unit) {
                return Err(Error::InvalidTheme(format!(
                    "spacing.unit {unit} is outside 2-16px"
                )));
            }
        }
        Ok(())
    }

    /// Fill in everything the document did not set.
    #[must_use]
    pub fn resolve(&self) -> ResolvedTheme {
        let defaults = builtin_palette(self.base);
        let mut colors = BTreeMap::new();
        for token in ColorToken::all() {
            let color = self
                .colors
                .get(token)
                .copied()
                .or_else(|| defaults.get(token).copied())
                // Unreachable in practice: the built-in palettes cover every
                // token, and a test asserts it. A fallback rather than an
                // unwrap, because a panic here would take the application down
                // over a colour.
                .unwrap_or(Color::rgb(127, 127, 127));
            colors.insert(*token, color);
        }
        ResolvedTheme {
            base: self.base,
            colors,
            sans: self
                .typography
                .sans
                .clone()
                .unwrap_or_else(|| "system-ui".to_owned()),
            mono: self
                .typography
                .mono
                .clone()
                .unwrap_or_else(|| "ui-monospace".to_owned()),
            base_size: self.typography.base_size.unwrap_or(14.0),
            scale: self.typography.scale.unwrap_or(1.25),
            radius_small: self.radius.small.unwrap_or(4),
            radius_medium: self.radius.medium.unwrap_or(8),
            radius_large: self.radius.large.unwrap_or(16),
            spacing_unit: self.spacing.unit.unwrap_or(4),
        }
    }
}

/// A font family name, with the characters that would make it a stylesheet
/// injection refused.
fn validate_font_family(family: &str) -> Result<()> {
    let bad = |why: &str| Err(Error::InvalidTheme(format!("font family '{family}' {why}")));
    if family.is_empty() || family.chars().count() > 64 {
        return bad("must be between 1 and 64 characters");
    }
    // The interface will interpolate this into a stylesheet. Every character
    // below either ends a declaration or opens a new construct, which is the
    // whole mechanism of CSS injection; a real family name needs none of them.
    //
    // The same set as the `fontFamily` pattern in
    // `eon-stream-spec/schemas/theme.v0.schema.json`, deliberately character
    // for character: a schema and an implementation that disagree about what
    // is acceptable produce a document that validates and then gets refused.
    if family.chars().any(|c| {
        matches!(
            c,
            ';' | '{' | '}' | '(' | ')' | '@' | '<' | '>' | '/' | '\\' | '"' | '\''
        )
    }) || family.chars().any(char::is_control)
    {
        return bad(
            "must be a family name only: a theme carries no code, and these characters \
             would let it inject a stylesheet",
        );
    }
    Ok(())
}

/// A theme with every token filled in: what an interface is handed.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedTheme {
    /// Which palette it was resolved against.
    pub base: ThemeBase,
    /// Every colour token.
    pub colors: BTreeMap<ColorToken, Color>,
    /// Sans-serif family name.
    pub sans: String,
    /// Monospace family name.
    pub mono: String,
    /// Base type size in CSS pixels.
    pub base_size: f64,
    /// Type scale ratio.
    pub scale: f64,
    /// Small corner radius.
    pub radius_small: u32,
    /// Medium corner radius.
    pub radius_medium: u32,
    /// Large corner radius.
    pub radius_large: u32,
    /// Base spacing unit.
    pub spacing_unit: u32,
}

impl ResolvedTheme {
    /// One colour.
    ///
    /// Infallible: a resolved theme has every token by construction.
    #[must_use]
    pub fn color(&self, token: ColorToken) -> Color {
        self.colors
            .get(&token)
            .copied()
            .unwrap_or(Color::rgb(127, 127, 127))
    }

    /// Every token as `name -> value` strings, which is the shape an interface
    /// or a stylesheet generator wants.
    #[must_use]
    pub fn tokens(&self) -> BTreeMap<String, String> {
        let mut tokens = BTreeMap::new();
        for (token, color) in &self.colors {
            tokens.insert(format!("color.{}", token.as_str()), color.to_hex());
        }
        tokens.insert("font.sans".to_owned(), self.sans.clone());
        tokens.insert("font.mono".to_owned(), self.mono.clone());
        tokens.insert("font.baseSize".to_owned(), format!("{}px", self.base_size));
        tokens.insert("font.scale".to_owned(), format!("{}", self.scale));
        tokens.insert(
            "radius.small".to_owned(),
            format!("{}px", self.radius_small),
        );
        tokens.insert(
            "radius.medium".to_owned(),
            format!("{}px", self.radius_medium),
        );
        tokens.insert(
            "radius.large".to_owned(),
            format!("{}px", self.radius_large),
        );
        tokens.insert(
            "spacing.unit".to_owned(),
            format!("{}px", self.spacing_unit),
        );
        tokens
    }

    /// WCAG contrast for every pair that actually gets rendered.
    ///
    /// The pairs are listed explicitly rather than computed over the cross
    /// product: `danger` against `success` is a ratio nobody looks at, and a
    /// report full of irrelevant pairs is a report that gets skimmed.
    #[must_use]
    pub fn contrast_report(&self) -> Vec<ContrastFinding> {
        let background = self.color(ColorToken::Background);
        let surface = self.color(ColorToken::Surface);
        let variant = self.color(ColorToken::SurfaceVariant);
        let accent = self.color(ColorToken::Accent);
        let danger = self.color(ColorToken::Danger);

        let pairs: &[(ColorToken, ColorToken, Color, ContrastRequirement)] = &[
            (
                ColorToken::Text,
                ColorToken::Background,
                background,
                ContrastRequirement::BodyText,
            ),
            (
                ColorToken::Text,
                ColorToken::Surface,
                surface,
                ContrastRequirement::BodyText,
            ),
            (
                ColorToken::Text,
                ColorToken::SurfaceVariant,
                variant,
                ContrastRequirement::BodyText,
            ),
            (
                ColorToken::TextMuted,
                ColorToken::Background,
                background,
                ContrastRequirement::BodyText,
            ),
            (
                ColorToken::TextMuted,
                ColorToken::Surface,
                surface,
                ContrastRequirement::BodyText,
            ),
            (
                ColorToken::AccentText,
                ColorToken::Accent,
                accent,
                ContrastRequirement::BodyText,
            ),
            (
                ColorToken::DangerText,
                ColorToken::Danger,
                danger,
                ContrastRequirement::BodyText,
            ),
            (
                ColorToken::Accent,
                ColorToken::Background,
                background,
                ContrastRequirement::Interface,
            ),
            (
                ColorToken::Focus,
                ColorToken::Background,
                background,
                ContrastRequirement::Interface,
            ),
            (
                ColorToken::Focus,
                ColorToken::Surface,
                surface,
                ContrastRequirement::Interface,
            ),
            (
                ColorToken::Border,
                ColorToken::Background,
                background,
                ContrastRequirement::Decoration,
            ),
            (
                ColorToken::Warning,
                ColorToken::Background,
                background,
                ContrastRequirement::Interface,
            ),
            (
                ColorToken::Success,
                ColorToken::Background,
                background,
                ContrastRequirement::Interface,
            ),
        ];

        pairs
            .iter()
            .map(|(foreground, back, backdrop, requirement)| {
                let ratio = self
                    .color(*foreground)
                    .contrast_ratio(self.color(*back), *backdrop);
                ContrastFinding {
                    foreground: *foreground,
                    background: *back,
                    ratio,
                    requirement: *requirement,
                }
            })
            .collect()
    }

    /// Contrast pairs that do not meet their requirement.
    #[must_use]
    pub fn contrast_failures(&self) -> Vec<ContrastFinding> {
        self.contrast_report()
            .into_iter()
            .filter(|finding| !finding.passes())
            .collect()
    }

    /// Whether every rendered pair meets its requirement.
    #[must_use]
    pub fn meets_contrast_requirements(&self) -> bool {
        self.contrast_failures().is_empty()
    }
}

/// What contrast a pair has to reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContrastRequirement {
    /// Text at normal size and weight: WCAG AA, 4.5:1.
    BodyText,
    /// Interface components and meaningful graphics: WCAG AA, 3:1.
    Interface,
    /// Purely decorative, such as a hairline between two rows. No
    /// requirement, reported so a theme author can see the number.
    Decoration,
}

impl ContrastRequirement {
    /// Message key for the verdict, for a host that renders its own text.
    ///
    /// [`ContrastFinding::describe`] is English-only and is a diagnostic; a
    /// host showing this to a person uses these keys and [`crate::i18n`]
    /// instead (madde 40).
    #[must_use]
    pub const fn verdict_key(self, passes: bool) -> &'static str {
        match (self, passes) {
            (Self::Decoration, _) => "cli.theme.contrast.notrequired",
            (_, true) => "cli.theme.contrast.ok",
            (_, false) => "cli.theme.contrast.failed",
        }
    }

    /// The ratio that has to be met, or `None` when nothing is required.
    #[must_use]
    pub const fn minimum(self) -> Option<f64> {
        match self {
            Self::BodyText => Some(4.5),
            Self::Interface => Some(3.0),
            Self::Decoration => None,
        }
    }
}

/// One measured pair.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ContrastFinding {
    /// The foreground token.
    pub foreground: ColorToken,
    /// The background token.
    pub background: ColorToken,
    /// The measured ratio.
    pub ratio: f64,
    /// What it had to reach.
    pub requirement: ContrastRequirement,
}

impl ContrastFinding {
    /// Whether it meets its requirement.
    #[must_use]
    pub fn passes(&self) -> bool {
        self.requirement
            .minimum()
            .is_none_or(|minimum| self.ratio >= minimum)
    }

    /// Message key for this finding's verdict.
    #[must_use]
    pub fn verdict_key(&self) -> &'static str {
        self.requirement.verdict_key(self.passes())
    }

    /// A line fit for a report.
    ///
    /// English, and a diagnostic: for text shown to a person, a host renders
    /// [`Self::verdict_key`] through its own catalogue.
    #[must_use]
    pub fn describe(&self) -> String {
        let verdict = match (self.requirement.minimum(), self.passes()) {
            (None, _) => "not required".to_owned(),
            (Some(minimum), true) => format!("ok (needs {minimum:.1})"),
            (Some(minimum), false) => format!("FAILS (needs {minimum:.1})"),
        };
        format!(
            "{} on {}: {:.2}:1 — {verdict}",
            self.foreground.as_str(),
            self.background.as_str(),
            self.ratio
        )
    }
}

/// The built-in palette for a base.
///
/// Both are chosen to pass their own contrast report, which the tests assert:
/// shipping a default that fails the check the project tells theme authors to
/// meet would make the check advice rather than a standard.
fn builtin_palette(base: ThemeBase) -> BTreeMap<ColorToken, Color> {
    let entries: &[(ColorToken, Color)] = match base {
        ThemeBase::Dark => &[
            (ColorToken::Background, Color::rgb(0x12, 0x14, 0x18)),
            (ColorToken::Surface, Color::rgb(0x1a, 0x1d, 0x23)),
            (ColorToken::SurfaceVariant, Color::rgb(0x23, 0x27, 0x2f)),
            (ColorToken::Text, Color::rgb(0xf2, 0xf4, 0xf8)),
            (ColorToken::TextMuted, Color::rgb(0xa8, 0xb0, 0xbf)),
            (ColorToken::Accent, Color::rgb(0x6f, 0xa8, 0xff)),
            (ColorToken::AccentText, Color::rgb(0x0a, 0x0c, 0x10)),
            (ColorToken::Border, Color::rgb(0x33, 0x38, 0x42)),
            (ColorToken::Danger, Color::rgb(0xff, 0x8a, 0x80)),
            (ColorToken::DangerText, Color::rgb(0x2a, 0x00, 0x00)),
            (ColorToken::Warning, Color::rgb(0xff, 0xc1, 0x6a)),
            (ColorToken::Success, Color::rgb(0x7a, 0xdc, 0xa0)),
            (ColorToken::Focus, Color::rgb(0x9a, 0xc4, 0xff)),
        ],
        ThemeBase::Light => &[
            (ColorToken::Background, Color::rgb(0xff, 0xff, 0xff)),
            (ColorToken::Surface, Color::rgb(0xf6, 0xf7, 0xf9)),
            (ColorToken::SurfaceVariant, Color::rgb(0xec, 0xee, 0xf2)),
            (ColorToken::Text, Color::rgb(0x14, 0x17, 0x1c)),
            (ColorToken::TextMuted, Color::rgb(0x55, 0x5c, 0x68)),
            (ColorToken::Accent, Color::rgb(0x11, 0x4e, 0xc4)),
            (ColorToken::AccentText, Color::rgb(0xff, 0xff, 0xff)),
            (ColorToken::Border, Color::rgb(0xc9, 0xcf, 0xd8)),
            (ColorToken::Danger, Color::rgb(0xa3, 0x16, 0x16)),
            (ColorToken::DangerText, Color::rgb(0xff, 0xff, 0xff)),
            (ColorToken::Warning, Color::rgb(0x7a, 0x4b, 0x00)),
            (ColorToken::Success, Color::rgb(0x11, 0x5c, 0x33)),
            (ColorToken::Focus, Color::rgb(0x0b, 0x3b, 0x99)),
        ],
    };
    entries.iter().copied().collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn colors_parse_in_every_accepted_form() {
        assert_eq!(Color::parse("#fff").unwrap(), Color::rgb(255, 255, 255));
        assert_eq!(Color::parse("#000").unwrap(), Color::rgb(0, 0, 0));
        assert_eq!(Color::parse("#1a2b3c").unwrap(), Color::rgb(26, 43, 60));
        assert_eq!(
            Color::parse("#1a2b3c80").unwrap(),
            Color {
                r: 26,
                g: 43,
                b: 60,
                a: 128
            }
        );
        // #rgba short form expands each nibble.
        assert_eq!(Color::parse("#f00f").unwrap(), Color::rgb(255, 0, 0));
    }

    #[test]
    fn malformed_colors_are_refused() {
        for bad in [
            "",
            "fff",
            "#",
            "#ff",
            "#fffff",
            "#gggggg",
            "#1a2b3c4",
            "red",
            "rgb(0,0,0)",
            "#1a2b3c4d5e",
        ] {
            assert!(Color::parse(bad).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn colors_render_in_one_spelling() {
        // However the document wrote it, resolved output is the long form.
        assert_eq!(Color::parse("#fff").unwrap().to_hex(), "#ffffff");
        assert_eq!(Color::parse("#FFFFFF").unwrap().to_hex(), "#ffffff");
        assert_eq!(Color::parse("#1a2b3c80").unwrap().to_hex(), "#1a2b3c80");
    }

    #[test]
    fn contrast_matches_the_published_wcag_numbers() {
        let white = Color::rgb(255, 255, 255);
        let black = Color::rgb(0, 0, 0);
        // Black on white is exactly 21:1.
        assert!((black.contrast_ratio(white, white) - 21.0).abs() < 0.01);
        // A colour against itself is 1:1.
        assert!((white.contrast_ratio(white, white) - 1.0).abs() < 0.001);
        // #767676 on white is the canonical 4.54:1 example from the WCAG
        // techniques -- the borderline case that catches a wrong luminance
        // formula.
        let grey = Color::rgb(0x76, 0x76, 0x76);
        let ratio = grey.contrast_ratio(white, white);
        assert!((4.5..4.6).contains(&ratio), "{ratio}");
    }

    #[test]
    fn translucent_text_is_measured_as_rendered() {
        // Treating #ffffff80 as white would report a passing contrast for text
        // that is in fact grey.
        let white_ish = Color::parse("#ffffff80").unwrap();
        let dark = Color::rgb(0x12, 0x14, 0x18);
        let as_rendered = white_ish.contrast_ratio(dark, dark);
        let as_written = Color::rgb(255, 255, 255).contrast_ratio(dark, dark);
        assert!(
            as_rendered < as_written,
            "{as_rendered} should be below {as_written}"
        );
        // And compositing is what makes that true.
        assert_eq!(white_ish.over(dark).a, 255);
    }

    #[test]
    fn both_builtin_palettes_pass_their_own_check() {
        // Shipping a default that fails the check theme authors are told to
        // meet would make the check advice rather than a standard.
        for base in [ThemeBase::Dark, ThemeBase::Light] {
            let resolved = ThemeDocument::plain(base).resolve();
            let failures = resolved.contrast_failures();
            assert!(
                failures.is_empty(),
                "{base:?} palette fails: {}",
                failures
                    .iter()
                    .map(ContrastFinding::describe)
                    .collect::<Vec<_>>()
                    .join("; ")
            );
        }
    }

    #[test]
    fn every_token_resolves() {
        let resolved = ThemeDocument::plain(ThemeBase::Dark).resolve();
        for token in ColorToken::all() {
            assert!(
                resolved.colors.contains_key(token),
                "{} is missing",
                token.as_str()
            );
        }
        // And the fallback grey never has to be used.
        assert!(!resolved
            .colors
            .values()
            .any(|c| *c == Color::rgb(127, 127, 127)));
    }

    #[test]
    fn an_unreadable_theme_is_reported_rather_than_refused() {
        // A theme author may be mid-edit; the document is valid, the contrast
        // report is what says it is unusable. Refusing to parse it would make
        // the report unreachable.
        let json = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 0,
            "base": "dark",
            "colors": { "text": "#131313", "background": "#121212" }
        }))
        .unwrap();
        let json = json.as_slice();
        let document = ThemeDocument::parse(json).unwrap();
        let resolved = document.resolve();
        assert!(!resolved.meets_contrast_requirements());
        let failures = resolved.contrast_failures();
        assert!(failures
            .iter()
            .any(|f| f.foreground == ColorToken::Text && f.background == ColorToken::Background));
        assert!(failures[0].describe().contains("FAILS"));
    }

    fn unknown_color_token() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 0,
            "base": "dark",
            "colors": { "notAToken": "#ffffff" }
        }))
        .expect("the test document serialises")
    }

    #[test]
    fn an_unknown_key_is_an_error_not_an_extension_point() {
        // There must be nowhere in a theme to put something a reader skips.
        for json in [
            br#"{"schemaVersion":0,"base":"dark","script":"alert(1)"}"#.as_slice(),
            // A colour value is written with json! here: a `"#` sequence
            // would terminate a single-hash raw literal mid-document.
            unknown_color_token().as_slice(),
            br#"{"schemaVersion":0,"base":"dark","typography":{"onLoad":"x"}}"#.as_slice(),
        ] {
            assert!(
                ThemeDocument::parse(json).is_err(),
                "{} should be refused",
                String::from_utf8_lossy(json)
            );
        }
    }

    #[test]
    fn a_font_family_cannot_carry_a_stylesheet() {
        // The interface will interpolate this into CSS. These are the shapes
        // that would make a theme into injection.
        for hostile in [
            "Inter; } body { display: none",
            "url(http://example.org/x.css)",
            "@import 'x'",
            "Inter\"",
            "Inter'",
            "Inter<script>",
            "//example.org",
        ] {
            let mut document = ThemeDocument::plain(ThemeBase::Dark);
            document.typography.sans = Some(hostile.to_owned());
            assert!(document.validate().is_err(), "{hostile} should be refused");
        }
        // An ordinary family name is fine, spaces and hyphens included.
        let mut document = ThemeDocument::plain(ThemeBase::Dark);
        document.typography.sans = Some("IBM Plex Sans".to_owned());
        document.typography.mono = Some("JetBrains Mono NL".to_owned());
        document.validate().unwrap();
    }

    #[test]
    fn unreadable_type_sizes_are_refused() {
        let mut document = ThemeDocument::plain(ThemeBase::Dark);
        document.typography.base_size = Some(2.0);
        assert!(document.validate().is_err());
        document.typography.base_size = Some(400.0);
        assert!(document.validate().is_err());
        document.typography.base_size = Some(16.0);
        document.validate().unwrap();
    }

    #[test]
    fn out_of_range_geometry_is_refused() {
        let mut document = ThemeDocument::plain(ThemeBase::Light);
        document.radius.medium = Some(1000);
        assert!(document.validate().is_err());

        let mut document = ThemeDocument::plain(ThemeBase::Light);
        document.spacing.unit = Some(0);
        assert!(document.validate().is_err());

        let mut document = ThemeDocument::plain(ThemeBase::Light);
        document.typography.scale = Some(10.0);
        assert!(document.validate().is_err());
    }

    #[test]
    fn an_unknown_schema_version_is_refused() {
        let json = br#"{"schemaVersion":1,"base":"dark"}"#;
        assert!(ThemeDocument::parse(json).is_err());
    }

    #[test]
    fn an_override_wins_and_the_rest_comes_from_the_base() {
        let json = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 0,
            "base": "dark",
            "colors": { "accent": "#ff00aa" },
            "radius": { "medium": 12 }
        }))
        .unwrap();
        let json = json.as_slice();
        let resolved = ThemeDocument::parse(json).unwrap().resolve();
        assert_eq!(resolved.color(ColorToken::Accent).to_hex(), "#ff00aa");
        assert_eq!(resolved.radius_medium, 12);
        // Untouched values come from the dark palette and its defaults.
        assert_eq!(resolved.radius_small, 4);
        assert_eq!(resolved.color(ColorToken::Background).to_hex(), "#121418");
    }

    #[test]
    fn tokens_are_flat_strings_an_interface_can_consume() {
        let tokens = ThemeDocument::plain(ThemeBase::Light).resolve().tokens();
        assert_eq!(
            tokens.get("color.background").map(String::as_str),
            Some("#ffffff")
        );
        assert_eq!(tokens.get("radius.small").map(String::as_str), Some("4px"));
        assert_eq!(
            tokens.get("font.baseSize").map(String::as_str),
            Some("14px")
        );
        // Every colour token appears.
        for token in ColorToken::all() {
            assert!(tokens.contains_key(&format!("color.{}", token.as_str())));
        }
    }

    #[test]
    fn a_document_round_trips_through_json() {
        let json = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 0,
            "base": "light",
            "colors": { "accent": "#114ec4", "text": "#14171c" },
            "typography": { "sans": "Inter", "baseSize": 15.0 },
            "radius": { "small": 2, "medium": 6, "large": 20 },
            "spacing": { "unit": 4 }
        }))
        .unwrap();
        let json = json.as_slice();
        let document = ThemeDocument::parse(json).unwrap();
        let text = serde_json::to_vec(&document).unwrap();
        assert_eq!(ThemeDocument::parse(&text).unwrap(), document);
    }

    #[test]
    fn decoration_pairs_are_reported_without_a_requirement() {
        let report = ThemeDocument::plain(ThemeBase::Dark)
            .resolve()
            .contrast_report();
        let border = report
            .iter()
            .find(|f| f.foreground == ColorToken::Border)
            .expect("the border pair is reported");
        assert_eq!(border.requirement, ContrastRequirement::Decoration);
        assert!(border.passes());
        assert!(border.describe().contains("not required"));
    }
}
