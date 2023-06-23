"""
# API Demo
This is a demo of the VulnCheck API, using the [Streamlit](https://streamlit.io) framework.

## Instructions
1. Enter your API key in the text box below.
2. Click the "Save" button.
3. Select the API function you want to use from the dropdown menu.
"""

import streamlit as st
import html
import requests
import re
import matplotlib.pyplot as plt
import pandas as pd
import requests
import json
import zipfile
import tempfile
import io
import os

st.title("VulnCheck API Explorer")

api_key = st.text_input(
    "VulnCheck API Key", 
    type="password",
    value=st.session_state.get("api_key", "")
)

def save():
    st.session_state["api_key"] = st.session_state.get('api_key', '')

st.button("Save", on_click=save)

FUNCTION_MAP = {
    "vulnerabilities-samples": "get_vulnerabilities_samples",
}

headers = {
    'Authorization': api_key
}

def get_exploit_score(exploit_data):
    if exploit_data is None:
        return 0

    score = 0
    # Increase the score based on the different attributes.
    # Adjust the weights as necessary.
    if exploit_data['weaponized_exploit_found']:
        score += 3
    if exploit_data['reported_exploited_by_ransomware']:
        score += 2
    if exploit_data['reported_exploited_by_threat_actors']:
        score += 2
    if exploit_data['reported_exploited']:
        score += 1

    # Also consider the counts (you can weigh these differently if you like)
    score += exploit_data['counts']['threat_actors']
    score += exploit_data['counts']['botnets']
    score += exploit_data['counts']['ransomware_families']
    
    return score


# Caching get_exploit_details() function
@st.cache_data()
def get_exploit_details(cve_id, token):
    url = "https://api.vulncheck.com/v3/index/exploits"
    headers = {
      "accept": "application/json",
      "authorization": f"Bearer {token}"
    }
    params = {
      'cve': cve_id
    }
    response = requests.get(url, headers=headers, params=params)
    
    if response.status_code == 200:
        data = response.json().get('data', [])
        if data:
            return data[0]
    else:
        print(f"Error {response.status_code}: Failed to retrieve exploit details")
        return None


# Caching get_vulnerabilities_samples() function
@st.cache_data()
def get_vulnerabilities_samples(url):
    response = requests.get(url)
    st.write("Loading data from API...")
    progress_bar = st.progress(0)

    try:
        with tempfile.TemporaryDirectory() as tempdir:
            with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                z.extractall(path=tempdir)
                
            data = []

            files = os.listdir(tempdir)
            num_files = len(files)
            
            for idx, filename in enumerate(files, start=1):
                if filename.endswith('.json'):
                    file_path = os.path.join(tempdir, filename)
                    with open(file_path) as f:
                        file_data = json.load(f)
                        for result in file_data.get('results', []):
                            cve_data = result.get('cve', {})

                            problemtype_data = cve_data.get('problemtype', {}).get('problemtype_data', [])
                            problemtype_name = problemtype_value = ''

                            if problemtype_data:
                                problemtype_desc = problemtype_data[0].get('description', [])
                            if problemtype_desc:
                                problemtype_name = problemtype_desc[0].get('name', '')
                                problemtype_value = problemtype_desc[0].get('value', '')

                            reference_data = cve_data.get('references', {}).get('reference_data', [])
                            references = []
                            for ref in reference_data:
                                name = ref.get('name', '')
                                url = ref.get('url', '')
                                if name and url:
                                    references.append(f"[{name}]({url})")
                            references_md = ' | '.join(references)

                            row_data = {
                                'id': file_data.get('id', ''),
                                'problemtype_name': problemtype_name,
                                'problemtype_value': problemtype_value,
                                'references': references_md,
                                'description': cve_data.get('description', {}),
                                'cve_data_meta': cve_data.get('CVE_data_meta', {}),
                                'baseMetricV2': result.get('impact', {}).get('baseMetricV2', {}),
                                'temporalMetricV3': result.get('impact', {}).get('temporalMetricV3', {}),
                                'temporalMetricV2': result.get('impact', {}).get('temporalMetricV2', {}),
                                'epss': result.get('impact', {}).get('epss', {}),
                                'related_attack_patterns': result.get('related_attack_patterns', []),
                            }
                            data.append(row_data)

                progress = idx / num_files
                progress_bar.progress(progress)
        
        df = pd.DataFrame(data)
        df = df[['id'] + [col for col in df.columns if col != 'id']]

        df['total_score'] = df.apply(lambda row: 
                                    row.get('baseMetricV2', {}).get('cvssV2', {}).get('baseScore', 0) +
                                    row.get('temporalMetricV3', {}).get('cvssV3', {}).get('temporalScore', 0) +
                                    10 * row.get('epss', {}).get('epss_score', 0), axis=1)

        # Then, sort the DataFrame based on the total_score.
        df = df.sort_values(by='total_score', ascending=False).head(25)

        # Fetch exploit data for each CVE ID and add to DataFrame
        df['exploit_data'] = df['id'].apply(lambda cve_id: get_exploit_details(cve_id, api_key))

        # Add the exploit scores to your DataFrame.
        df['exploit_score'] = df['exploit_data'].apply(get_exploit_score)

        # Create combined_score by adding total_score and exploit_score
        df['combined_score'] = df['total_score'] + df['exploit_score']

        # Then, sort the DataFrame based on the combined_score.
        df = df.sort_values(by='combined_score', ascending=False).head(25)

    except zipfile.BadZipFile as e:
        st.write(f"Error: {str(e)}")
    return df

# Caching get_backup_list function
@st.cache_data()
def get_backup_list(api_key):

    response = requests.get("https://api.vulncheck.com/v2/backup/list", headers=headers)

    if response.status_code == 200:
        data = response.json()

        for item in data:
            item["time_added"] = pd.to_datetime(item["time_added"], unit="ns", origin="unix")

        df = pd.DataFrame(data)

        return df
    else:
        return None

if api_key not in ["", None]:
    df = get_backup_list(api_key)

    if df is not None:
        """
        ### Show the top 25 CVEs, rank-ordered by total score
        """

        for idx, row in df.iterrows():
            if row['file_type'] in FUNCTION_MAP:
                if st.button(f"Run {row['file_type']} demos"):
                    function_name = FUNCTION_MAP[row['file_type']]
                    results_df = globals()[function_name](row['url'])  
                    if results_df is not None:
                        for result_idx, result_row in results_df.iterrows():
                            st.markdown(f"# {result_row['id']}")

                            # setup two columns
                            col1, col2 = st.columns(2)
                            col1.markdown(f"**CWE Name**: {result_row['problemtype_name']}")
                            col2.markdown(f"**CWE Value**: {result_row['problemtype_value']}")

                            description = result_row['description']['description_data'][0]['value']
                            st.markdown(f"**Description**: {html.escape(description)}", unsafe_allow_html=True)
                            st.markdown(f"**CNA**: {result_row['cve_data_meta']['ASSIGNER']}")

                            exploit_details = get_exploit_details(result_row['id'], api_key)
                            if exploit_details:
                                first_exploit_published = exploit_details['timeline'].get('first_exploit_published', 'N/A')
                                first_exploit_published_weaponized_or_higher = exploit_details['timeline'].get('first_exploit_published_weaponized_or_higher', 'N/A')
                                most_recent_exploit_published = exploit_details['timeline'].get('most_recent_exploit_published', 'N/A')
                                # clean these dates up, 2020-08-09T05:48:10Z is too long
                                first_exploit_published = first_exploit_published.split('T')[0]
                                first_exploit_published_weaponized_or_higher = first_exploit_published_weaponized_or_higher.split('T')[0]
                                most_recent_exploit_published = most_recent_exploit_published.split('T')[0]

                                # Convert boolean values to emojis
                                public_exploit_found_emoji = '✅' if exploit_details['public_exploit_found'] else '❌'
                                weaponized_exploit_found_emoji = '✅' if exploit_details['weaponized_exploit_found'] else '❌'
                                reported_exploited_by_threat_actors_emoji = '✅' if exploit_details['reported_exploited_by_threat_actors'] else '❌'
                                reported_exploited_by_ransomware_emoji = '✅' if exploit_details['reported_exploited_by_ransomware'] else '❌'
                                reported_exploited_by_botnets_emoji = '✅' if exploit_details['reported_exploited_by_botnets'] else '❌'

                                # Construct a DataFrame from exploit details
                                exploit_df = pd.DataFrame({
                                    'Public Exploit Found': [public_exploit_found_emoji],
                                    'Weaponized Exploit Found': [weaponized_exploit_found_emoji],
                                    'Reported Exploited By Threat Actors': [reported_exploited_by_threat_actors_emoji],
                                    'Reported Exploited By Ransomware': [reported_exploited_by_ransomware_emoji ],
                                    'Reported Exploited By Botnets': [reported_exploited_by_botnets_emoji],
                                    'First Exploit Published': [first_exploit_published],
                                    'First Exploit Published (Weaponized or higher)': [first_exploit_published_weaponized_or_higher],
                                    'Most Recent Exploit Published': [most_recent_exploit_published],
                                })

                                # Display the DataFrame
                                st.markdown("## Exploit Details")
                                st.table(exploit_df)

                            st.markdown("## Metrics")
                            baseScoreV2 = result_row.get('baseMetricV2', {}).get('cvssV2', {}).get('baseScore', 0)
                            baseScoreV3 = result_row.get('temporalMetricV3', {}).get('cvssV3', {}).get('temporalScore', 0)
                            epss_score = result_row.get('epss', {}).get('epss_score', 0)

                            col1, col2, col3 = st.columns(3)
                            
                            col1.metric("CVSSv2", baseScoreV2, 10)
                            col2.metric("CVSSv3", baseScoreV3, 10)
                            col3.metric("EPSS", epss_score, 1)

                            attack_pattern_count = len(result_row.get('related_attack_patterns', []))  # Get the length of the list as the count
                            st.markdown(f"**Related Attack Patterns Count**: {attack_pattern_count}")
                            st.markdown("---")
    else:
        st.write("Invalid API key")
