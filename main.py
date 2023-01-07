import streamlit as st
from streamlit_lottie import st_lottie
import requests
import hashlib
import pandas as pd
import matplotlib.pyplot as plt
import time
import sqlite3

conn = sqlite3.connect('data.db')
c = conn.cursor()

st.set_page_config(page_title="CyberSentry - Aim to assist security analysts.", layout="wide")
st.markdown(
    """
    <style>
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    </style>
    """, unsafe_allow_html=True,)

def create_usertable():
    c.execute('CREATE TABLE IF NOT EXISTS userstable(username TEXT,password TEXT)')


def add_userdata(username, password):
    c.execute('INSERT INTO userstable(username,password) VALUES (?,?)', (username, password))
    conn.commit()


def login_user(username, password):
    c.execute('SELECT * FROM userstable WHERE username =? AND password = ?', (username, password))
    data = c.fetchall()
    return data


def make_hashes(password):
    return hashlib.sha256(str.encode(password)).hexdigest()


def check_hashes(password, hashed_text):
    if make_hashes(password) == hashed_text:
        return hashed_text
    return False


@st.experimental_memo
def load_lottie(url):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()


animation = load_lottie("https://assets1.lottiefiles.com/packages/lf20_dews3j6m.json")
animation2 = load_lottie("https://assets1.lottiefiles.com/private_files/lf30_4y2cuiyr.json")

@st.experimental_memo
def get_data(limit, page):
    url = f"https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since=2017-03-01&limit={limit}&page={page}"
    headers = {'X-OTX-API-KEY': st.secrets["key"]}
    response = requests.get(url, headers=headers)
    data = response.json()
    pulses = data['results']
    return pulses


@st.experimental_memo
def get_anlaytics_data(pulse_id):
    headers = {'X-OTX-API-KEY': st.secrets["key"]}
    response = requests.get(f'https://otx.alienvault.com/api/v1/pulses/{pulse_id}', headers=headers)
    data = response.json()
    return data


@st.experimental_memo
def analytics_ioc():
    ioc_list = []
    for pulse in pulses:
        pulse_id = (pulse['id'])
        data = get_anlaytics_data(pulse_id)
        for items in data['indicators']:
            ioc_list.append(items['type'])
    return ioc_list


@st.experimental_memo
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


st.sidebar.title("Welcome to CyberSentry")
st.sidebar.markdown("""---""")
st.markdown("<div style='margin-top: -100px;background-color: rgb(14, 17, 23); color:#f1f1f1; text-align:center;'><h1>CyberSentry<sub><i>Aim To Assist Security Analysts</i></sub></h1></div>", unsafe_allow_html=True)
st.write("##")
menu = ["Home", "Login", "SignUp"]
choice = st.sidebar.selectbox("Navigation Menu", menu)
st.sidebar.markdown("""---""")
if choice == "Home":
    st.markdown("""
    <style>
    .css-1r6slb0.e1tzin5v2 {
            border: 1px solid black;
            padding: 10px;
            /* background-color: #f1f1f1; */
            border-radius: 15px;
            #overflow: scroll;
            height: 400px;
            box-shadow: 10px 10px 5px 0px rgba(0,0,0,0.75);
            letter-spacing: 2px;
            display: flex;
            align-items: center;
            transition: transform 0.5s;
            }
    .css-1r6slb0.e1tzin5v2:hover{
            transform: scale(0.96);
            }
    </style>
    """,unsafe_allow_html=True)
    st.subheader("Get Real Time Threats and Advanced Analytics")
    left_column, right_column = st.columns(2)
    with left_column:
        string = "About CyberSentry:<ul>Welcome to CyberSentry, where we provide real-time cyber threat intelligence and advanced " \
                 "analytics to assist security analysts in protecting their organizations. Our state-of-the-art " \
                 "technology allows security teams to stay ahead of potential threats and respond quickly to any " \
                 "incidents that may occur.</ul>"
        st.write(string, unsafe_allow_html=True)
    with middle_column:
        string = "Key Features:" \
                 "<li>More Than 500 Threats From Across The World.</li><li>Analytics of Threats Categorized By " \
                 "Countries.</li><li>In Depth Details of Each Threat. " \
                 "</li><li>Analytics of IOC Collected From All Threats. " \
                 "</li><li>Rule Generator For Intrusion Detection System." \
                 "</li>"
        st.write(string, unsafe_allow_html=True)
    with right_column:
        st_lottie(animation2, height=300, key="hacking")
        # st_lottie(animation, height=300, key="analytics")

elif choice == "Login":
    st.sidebar.header("Login Section")

    username = st.sidebar.text_input("User Name")
    password = st.sidebar.text_input("Password", type='password')

    login = st.sidebar.checkbox("Login/Log out")
    if login:
        st.markdown("""
        <style>
        .css-1r6slb0.e1tzin5v2 {
            border: 1px solid black;
            padding: 10px;
            background-color: rgb(14, 17, 23);
            border-radius: 15px;
            overflow: scroll;
            height: 600px;
            box-shadow: 10px 10px 5px 0px rgba(0,0,0,0.75);
        }
        .css-keje6w.e1tzin5v2 {
            border: 1px solid black;
            padding: 10px;
            /* background-color: #f1f1f1; */
            border-radius: 15px;
            overflow: scroll;
            height: 600px;
            box-shadow: 10px 10px 5px 0px rgba(0,0,0,0.75);
}
        .css-1l269bu.e1tzin5v2 {
            border: 1px solid black;
            padding: 10px;
            background-color: rgb(14, 17, 23);
            border-radius: 15px;
            overflow: scroll;
            height: 600px;
            box-shadow: 10px 10px 5px 0px rgba(0,0,0,0.75);
}
        </style>
        """, unsafe_allow_html=True)
        create_usertable()
        hashed_pswd = make_hashes(password)
        result = login_user(username, check_hashes(password, hashed_pswd))
        if result:
            left_column, middle_column, right_column = st.columns([1, 2, 3])
            with left_column:
                # Get the current time
                now = time.time()
                # Extract the information you need
                hour = time.localtime(now).tm_hour
                minute = time.localtime(now).tm_min
                second = time.localtime(now).tm_sec
                st.success(f"Logged in as {username}. All data are up to date as of now {hour}:{minute}:{second}")
                st.subheader("Select Country")
                countries = ["United States of America", "Korea, Republic of", "United Arab Emirates", "Israel",
                             "India", "Canada", "Ukraine"]
                selected_country = st.selectbox("Select Your Country", countries)
                pages = ["1", "2", "3", "4", "5"]
                selected_page = st.selectbox("Load More Threats", pages)
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

            with middle_column:
                if selected_country and selected_page:
                    st.subheader(f"These Threats Are Targeting {selected_country}")
                    pulses = get_data(100, selected_page)
                    # Print the titles of the pulses
                    for pulse in pulses:
                        for items in pulse['targeted_countries']:
                            if items == selected_country:
                                st.info('Title: ' + (pulse['name']))
                                st.write('<b>PulseId</b>: ' + (pulse['id']), unsafe_allow_html=True)
                                st.write('<b>Description</b>: ' + (pulse['description']), unsafe_allow_html=True)
                                st.markdown("""---""")

            with right_column:
                tab1, tab2, tab3, tab4 = st.tabs(["Targeting Countries", "All 100 Threats", "IOC Percentages", "IDS Rule"])
                with tab1:
                    st.subheader("Threats Targeteing Countries")
                    with st.spinner('Generating Graph...'):
                        time.sleep(5)
                        pulses = get_data(100, selected_page)
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
                        st.markdown("""---""")

                with tab2:
                    st.subheader("All Threats")
                    pulses = get_data(100, selected_page)
                    # Print the titles of the pulses
                    for pulse in pulses:
                        st.write('<b>Title</b>: ' + (pulse['name']), unsafe_allow_html=True)
                        st.write('<b>PulseId</b>: ' + (pulse['id']), unsafe_allow_html=True)
                        st.write('<b>Description</b>: ' + (pulse['description']), unsafe_allow_html=True)
                        st.markdown("""---""")
                with tab3:
                    st.subheader("Analytics - IOC Types")
                    ioc_list = analytics_ioc()
                    country_counts = {}
                    for country in ioc_list:
                        if country in country_counts:
                            country_counts[country] += 1
                        else:
                            country_counts[country] = 1
                    df = pd.DataFrame.from_dict(country_counts, orient='Index', columns=['Amount'])
                    with st.spinner(text="Generating Table"):
                        pie_chart_ioc(ioc_list)
                        st.table(df)
                        st.markdown("""---""")
                with tab4:
                    st.subheader("Snort Rule Generator")
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
                    st.markdown("""---""")
        else:
            st.error("Incorrect Username/Password")
    else:
        st.warning("LogIn or SignUp From The Navigation Menu")



elif choice == "SignUp":
    st.subheader("Create New Account")
    new_user = st.text_input("Username")
    new_password = st.text_input("Use Strong Password", type='password')

    if st.button("SignUp"):
        create_usertable()
        add_userdata(new_user, make_hashes(new_password))
        st.success("You have successfully created a valid account.")
        st.info("Go to Login Menu to login")

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
        background-color: #262730;
        color: white;
    }
    </style>
    <div class="footer">
        &copy; All Right Reserved by Tasin Naveed 2022
    </div>

    """,
    unsafe_allow_html=True,
)

