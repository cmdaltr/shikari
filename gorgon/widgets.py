#!/usr/bin/env python3 -tt
from ipywidgets import HBox, VBox, widgets

out = widgets.Output()
hspacer = widgets.Box(layout=widgets.Layout(height="10px"))
wspacer = widgets.Box(layout=widgets.Layout(width="10px"))
multispacer = HBox(
    [wspacer, wspacer, wspacer, wspacer, wspacer, wspacer, wspacer, wspacer]
)


def format_initial_widgets(
    group_name,
    indicies_dropdown,
    org_dropdown,
    hypothesis,
    continue_button,
):
    vectr_heading = widgets.Label(value="Threat Actor")
    vectr_sub1 = widgets.Label(value="Provide a name of the Threat Actor.")
    vectr_sub2 = widgets.Label(
        value="Select which Index and Organization to attach and provide a clear detailed hypothesis."
    )
    # stylising labels
    vectr_heading.style.font_size = "22px"
    vectr_heading.style.font_weight = "bold"
    vectr_sub1.style.font_size = "14px"
    vectr_sub2.style.font_size = "14px"

    # use case
    index_org = HBox(
        [
            indicies_dropdown,
            multispacer,
            wspacer,
            org_dropdown,
        ]
    )
    widgets_text = VBox(
        [
            hspacer,
            vectr_heading,
            hspacer,
            vectr_sub1,
            group_name,
            hspacer,
            vectr_sub2,
            index_org,
            hspacer,
            hypothesis,
            hspacer,
            continue_button,
        ]
    )

    initial_widgets = VBox(
        [
            widgets_text,
            hspacer,
        ]
    )
    return initial_widgets


def initial_input(indicies, orgs, continue_button, widget_style):
    group_name = widgets.Text(
        value="Scattered Spider",
        placeholder="Scattered Spider",
        hypothesis="Assessment:",
        style=widget_style,
        layout={"width": "664px"},
    )
    org_dropdown = widgets.Dropdown(
        options=orgs,
        hypothesis="Organization:",
        style=widget_style,
        layout={"width": "max-content"},
    )
    indicies_dropdown = widgets.Dropdown(
        options=indicies,
        hypothesis="Index:",
        style=widget_style,
        layout={"width": "max-content"},
    )
    hypothesis = widgets.Textarea(
        value="Scattered Spider is targeting financial institutions, using spear-phishing campaigns to deliver custom malware (e.g., RoyalDNS or Okrum) via malicious documents, followed by C2 communications over DNS or HTTPS to known Scattered Spider infrastructure.",
        placeholder="Scattered Spider is targeting financial institutions, using spear-phishing campaigns to deliver custom malware (e.g., RoyalDNS or Okrum) via malicious documents, followed by C2 communications over DNS or HTTPS to known Scattered Spider infrastructure.",
        hypothesis="Hypothesis:",
        style=widget_style,
        layout={"width": "664px", "height": "80px"},
    )

    initial_widgets = format_initial_widgets(
        group_name,
        indicies_dropdown,
        org_dropdown,
        hypothesis,
        continue_button,
    )

    return (
        initial_widgets,
        group_name,
        indicies_dropdown,
        org_dropdown,
        hypothesis,
    )


def format_mitre_widgets(
    tactic_dropdown,
    technique_multi,
    add_button,
):
    mitre_heading = widgets.Label(value="Mitre ATT&CK mapping")
    mitre_sub1 = widgets.Label(
        value="Select the most relevant Tactic for the test cases you want to create."
    )
    mitre_sub2 = widgets.Label(
        value="Select the techniques which fall under the above Tactic - it does not need to match MITRE ATT&CK."
    )
    mitre_sub3 = widgets.Label(
        value="Once you have clicked ADD, you can return here and select another Tactic and set of Techniques."
    )
    # stylising labels
    mitre_heading.style.font_size = "22px"
    mitre_heading.style.font_weight = "bold"
    mitre_sub1.style.font_size = "14px"
    mitre_sub2.style.font_size = "14px"

    widgets_text = VBox(
        [
            hspacer,
            mitre_heading,
            hspacer,
            mitre_sub1,
            tactic_dropdown,
            hspacer,
            mitre_sub2,
            technique_multi,
            hspacer,
            mitre_sub3,
            add_button,
        ]
    )

    mitre_widgets = VBox(
        [
            widgets_text,
            hspacer,
        ]
    )
    return mitre_widgets


def mitre_input(
    phases,
    techniques,
    add_button,
    widget_style,
):
    tactic_dropdown = widgets.Dropdown(
        options=phases,
        hypothesis="Tactic:",
        style=widget_style,
        layout={"width": "max-content"},
    )
    technique_multi = widgets.SelectMultiple(
        options=techniques,
        hypothesis="Techniques:",
        style=widget_style,
        layout={"width": "max-content"},
        rows=round(len(techniques) / 20),
    )

    mitre_widgets = format_mitre_widgets(
        tactic_dropdown,
        technique_multi,
        add_button,
    )

    # build mitre_widgets based on the above variables and values
    return (
        mitre_widgets,
        tactic_dropdown,
        technique_multi,
    )


def format_additional_input(
    technique_name,
    op_guidance_text,
    red_tools_text,
    detect_guidance_text,
):
    additional_sub = widgets.Label(
        value=f"Select complete the respective information for technique: {technique_name}"
    )
    additional_sub.style.font_size = "14px"

    widgets_text = VBox(
        [
            hspacer,
            additional_sub,
            hspacer,
            op_guidance_text,
            hspacer,
            red_tools_text,
            hspacer,
            detect_guidance_text,
        ]
    )

    additional_widgets = VBox(
        [
            widgets_text,
            hspacer,
        ]
    )

    return additional_widgets


def additional_input(technique_name, widget_style):
    op_guidance_text = widgets.Textarea(
        value="",
        placeholder="Offensive operation commands e.g. SEKURLSA::Pth",
        hypothesis="Op. Guidance:",
        style=widget_style,
        layout={"width": "664px"},
    )
    red_tools_text = widgets.Textarea(
        value="",
        placeholder="Offensive operation tools e.g. mimikatz",
        hypothesis="Red Tools:",
        style=widget_style,
        layout={"width": "664px"},
    )
    detect_guidance_text = widgets.Textarea(
        value="",
        placeholder="Means of detecting offensive activity...",
        hypothesis="Detection:",
        style=widget_style,
        layout={"width": "664px"},
    )

    additional_widgets = format_additional_input(
        technique_name,
        op_guidance_text,
        red_tools_text,
        detect_guidance_text,
    )

    return (
        additional_widgets,
        op_guidance_text,
        red_tools_text,
        detect_guidance_text,
    )


def format_submit_input(submit_button):
    vectr_heading = widgets.Label(value="Submit Test Case(s): ")
    # stylising labels
    vectr_heading.style.font_size = "22px"

    # use case
    widgets_text = HBox(
        [vectr_heading, wspacer, wspacer, wspacer, wspacer, submit_button]
    )

    submit_widgets = VBox(
        [
            hspacer,
            widgets_text,
            hspacer,
        ]
    )
    return submit_widgets


def submit_input(submit_button):
    submit_widgets = format_submit_input(
        submit_button,
    )

    return submit_widgets
