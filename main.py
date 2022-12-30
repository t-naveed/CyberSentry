import time
import requests
import streamlit as st

import matplotlib.pyplot as plt
import pandas as pd
from streamlit_lottie import st_lottie


st.set_page_config(page_title="CyberSentry - Aim to assist security analysts.",layout="wide")

st.markdown(
    """
    <style>
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    </style>
    """, unsafe_allow_html=True,)



# -------- Lottie Asset -------- #
@st.experimental_memo
def load_lottie(url):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()


animation = load_lottie("https://assets4.lottiefiles.com/packages/lf20_mcvtkrvc.json")


#@st.cache(allow_output_mutation=True, hash_funcs={"_thread.RLock": lambda _: None})
@st.experimental_memo
def get_data(limit, page):
    url = f"https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since=2017-03-01&limit={limit}&page={page}"
    headers = {'X-OTX-API-KEY': st.secrets["key"]}
    response = requests.get(url, headers=headers)
    data = response.json()
    pulses = data['results']
    return pulses


#@st.cache(allow_output_mutation=True, hash_funcs={"_thread.RLock": lambda _: None})
@st.experimental_memo
def get_anlaytics_data(pulse_id):
    headers = {'X-OTX-API-KEY': st.secrets["key"]}
    response = requests.get(f'https://otx.alienvault.com/api/v1/pulses/{pulse_id}', headers=headers)
    data = response.json()
    return data


def pie_chart_ioc(ioc_type_list):
    category_counts = {}
    for category in ioc_type_list:
        if category in category_counts:
            category_counts[category] += 1
        else:
            category_counts[category] = 1
    # Get the categories and their counts as separate lists
    categories = list(category_counts.keys())
    counts = list(category_counts.values())
    plt.pie(counts, labels=categories, autopct='%1.1f%%', shadow=False, startangle=90)
    plt.axis('equal')
    # Add a title
    plt.title("IOC Type Percentages", fontsize=5)
    # Set the font size for the labels
    plt.rcParams.update({'font.size': 4})
    # Add a legend
    plt.legend(title="Categories", loc="lower right")
    plt.gcf().set_size_inches(3, 3)
    # Display the chart
    st.pyplot()


def first_tab():
    left_column, right_column = st.columns(2)
    with left_column:
        st.subheader("These Threats Are Targeting USA")
        pulses = get_data(100, 1)
        # Print the titles of the pulses
        for pulse in pulses:
            for items in pulse['targeted_countries']:
                if items == "United States of America":
                    st.write('<b>Title</b>: ' + (pulse['name']), unsafe_allow_html=True)
                    st.write('<b>PulseId</b>: ' + (pulse['id']), unsafe_allow_html=True)
                    st.write('<b>Description</b>: ' + (pulse['description']), unsafe_allow_html=True)
                    st.markdown("""---""")
    with right_column:
        st.subheader("Threats Targeteing Countries")
        with st.spinner('Generating Graph...'):
            time.sleep(5)
            pulses = get_data(100, 1)
            country_list = []
            for pulse in pulses:
                pulse_id = (pulse['id'])
                data = get_anlaytics_data(pulse_id)
                for items in data['targeted_countries']:
                    country_list.append(items)

            country_counts = {}
            for country in country_list:
                if country in country_counts:
                    country_counts[country] += 1
                else:
                    country_counts[country] = 1

                # Create a DataFrame from the dictionary of country counts
            df = pd.DataFrame.from_dict(country_counts, orient='index', columns=['Targeted Threats'])

            # Create a bar chart with the DataFrame
            st.bar_chart(df, height=520)

        st.subheader("Snot Rule Generator")
        alert_type = st.selectbox("Select The Type of Alert You Want To Generate",
                                  ('Domain', 'FileHash-SHA256', 'ipv4'))
        if alert_type == 'Domain':
            domain = st.text_input("Enter Domain Name")
            if domain:
                rule = domain_rule(domain)
                st.success(rule)
        if alert_type == 'FileHash-SHA256':
            FileHashSHA256 = st.text_input("Enter FileHash-SHA256")
            if FileHashSHA256:
                rule = hash_256_rule(FileHashSHA256)
                st.success(rule)
        if alert_type == 'ipv4':
            ipv4 = st.text_input("Enter ipv4 address here")
            if ipv4:
                rule = ipv4_rule(ipv4)
                st.success(rule)


def sidebar():
    st.subheader("Get Threat Details")
    pulse_id = st.text_input("Input PulseId To See Details", key='for-details')
    if pulse_id:
        with st.spinner(text="Gathering Details"):
            data = get_anlaytics_data(pulse_id)
            adversary = data['adversary']
            targeted_countries = data['targeted_countries']
            malware_families = data["malware_families"]
            # st.write(data)
            ioc_type = []
            with st.expander("Indicator of Compromise"):
                for items in data['indicators']:
                    ioc_type.append(items['type'])
                    st.write('<b>Indicator: </b>' + items['indicator'], unsafe_allow_html=True)
                    st.write('<b>Type: </b>' + items['type'], unsafe_allow_html=True)

            with st.expander("Adversary"):
                st.write("<b>Adversary: </b>" + adversary, unsafe_allow_html=True)
            with st.expander("Targeted Countries"):
                st.write('<b>Targeted Countries are: </b>', unsafe_allow_html=True)
                for items in data['targeted_countries']:
                    if items == 0:
                        st.write("Targeted Countries are Unknown")
                    else:
                        st.write(items)
            with st.expander("Malware Families"):
                st.write('<b>Malware Families: </b>', unsafe_allow_html=True)
                for items in data['malware_families']:
                    if items == 0:
                        st.write("Targeted Countries are Unknown")
                    else:
                        st.write(items)
            with st.expander("References"):
                st.write('<b>References: </b>', unsafe_allow_html=True)
                for items in data['references']:
                    if items == 0:
                        st.write("Targeted Countries are Unknown")
                    else:
                        st.write(items)
    else:
        st.warning("Input PusleID and hit enter")


@st.experimental_memo
def analytics_ioc():
    ioc_list = []
    for pulse in pulses:
        pulse_id = (pulse['id'])
        data = get_anlaytics_data(pulse_id)
        for items in data['indicators']:
            ioc_list.append(items['type'])
    return ioc_list

def domain_rule(domain):
    domain = domain
    rule = "alert tcp any any -> any 80 (msg:\"Traffic to Domain {}\"; content:\"Host: {}\"; sid:1;)"
    snort_rule = rule.format(domain, domain)
    return (snort_rule)


def hash_256_rule(file_hash):
    file_hash = file_hash
    rule = "alert tcp any any -> any any (msg:\"Traffic with FileHash-SHA256 {}\"; content:\"FileHash-SHA256: {}\"; sid:1;)"
    snort_rule = rule.format(file_hash, file_hash)
    return (snort_rule)


def ipv4_rule(ip_addr):
    ip_address = ip_addr
    rule = "alert tcp {} any -> any any (msg:\"Traffic from IP Address {}\"; sid:1;)"
    snort_rule = rule.format(ip_address, ip_address)
    return (snort_rule)

st.markdown("<style>block-container.css-18e3th9.egzxvld2{margin-top: -180px;}</style>", unsafe_allow_html=True)
st.markdown("<h1>CyberSentry<sub><i>Aim To Assist Security Analysts</i></sub></h1>", unsafe_allow_html=True)
st.write("###")
st.write("###")
left_column, right_column = st.columns(2)
time.sleep(8)
with left_column:
    st.subheader("Get Real Time Threats and Advanced Analytics")
    string = "At CyberSentry, our mission is to provide real-time threat intelligence and advanced analytics " \
                 "to help security analysts stay ahead of potential threats. Checkout different tabs to find latest " \
                 "threats and analytics."
    st.write(string, unsafe_allow_html=True)
with right_column:
    st_lottie(animation, height=300, key="hacking")

tab_one, tab_two = st.sidebar.tabs(["Get Threat Details", "More"])
with tab_one:
    sidebar()
with tab_two:
    st.write("More features")
tab1, tab2, tab3 = st.tabs(["Threats Targeting Countries", "All Subscribed Threats", "More"])
with tab1:
    first_tab()
with tab2:
    left_column, right_column = st.columns(2)
    with left_column:
        st.subheader("Latest Threats")
        pulses = get_data(100, 1)
            # Print the titles of the pulses
        for pulse in pulses:
            st.write('<b>Title</b>: ' + (pulse['name']), unsafe_allow_html=True)
            st.write('<b>PulseId</b>: ' + (pulse['id']), unsafe_allow_html=True)
            st.write('<b>Description</b>: ' + (pulse['description']), unsafe_allow_html=True)
            st.markdown("""---""")
    with right_column:
        st.subheader("Analytics - IOC Types")
        ioc_list = analytics_ioc()
        country_counts = {}
        for country in ioc_list:
            if country in country_counts:
                country_counts[country] += 1
            else:
                country_counts[country] = 1
        df = pd.DataFrame.from_dict(country_counts, orient='Index', columns=['Amount'])
        option = st.selectbox("View in table or pie chart", ('Table', 'Pie Chart', 'Bar Chart'))
        if option == 'Table':
            with st.spinner(text="Generating Table"):
                st.table(df)
        if option == 'Pie Chart':
            with st.spinner(text="Generating Pie Chart"):
                pie_chart_ioc(ioc_list)
            # Create a bar chart with the DataFrame
        if option == 'Bar Chart':
            with st.spinner(text="Generating Bar Chart"):
                st.bar_chart(df, height=520)
# else:
#
#     st.markdown("<h1>CyberSentry<sub><i>Aim To Assist Security Analysts</i></sub></h1>", unsafe_allow_html=True)
#     st.subheader("Get Real Time Threats and Advanced Analytics")
#     st.write("###")
#     string = "At CyberSentry, our mission is to provide real-time threat intelligence and advanced analytics " \
#              "to help security analysts stay ahead of potential threats. Our platform offers detailed information " \
#              "about the latest cyber threats, including the types of attacks being carried out and the countries " \
#              "that are most frequently targeted. With our advanced analytics capabilities, security teams can " \
#              "gain a deeper understanding of the threats they face and develop more effective strategies for " \
#              "protecting their organizations. We are committed to helping our clients achieve the highest level " \
#              "of security possible and to stay ahead of the constantly evolving threat landscape."
#     st.write(string, unsafe_allow_html=True)
st.markdown(
    """
    <style>
    .footer {
        position: fixed;
        left: 0;
        bottom: 0;
        width: 100%;
        height: 60px;
        display: flex;
        align-items: center;
        justify-content: center;
        background-color: #F0F2F6;
        color: #31333F;
    }
    </style>
    <div class="footer">
        &copy; All Right Reserved by Tasin Naveed 2022
    </div>

    """,
    unsafe_allow_html=True,
)
