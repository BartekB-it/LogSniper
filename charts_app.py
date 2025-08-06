import streamlit as st
import os
import json
import pandas as pd
import matplotlib.pyplot as plt
import folium
from streamlit_folium import st_folium

st.title("LogSniper Results Dashboard")

files = [f for f in os.listdir("results") if f.endswith(".json")]
selected_file = st.selectbox("Select results file:", files)

if selected_file:
    with open(f"results/{selected_file}", "r") as f:
        data = json.load(f)

    df = pd.DataFrame(data)

    st.write("Results Table:")
    st.dataframe(df)

    classification_counts = df['classification'].value_counts()

    st.write("Classification Count Bar Chart:")
    fig, ax = plt.subplots()
    classification_counts.plot(kind='bar', ax=ax)
    st.pyplot(fig)

    classification_filter = st.selectbox("Filter data by classification:", classification_counts.index)
    filtered_df = df[df['classification'] == classification_filter]

    st.write(f"Results for classification: {classification_filter}")
    st.dataframe(filtered_df)

    if 'lat' in df.columns and 'lon' in df.columns:
        df['lat'] = pd.to_numeric(df['lat'], errors='coerce')
        df['lon'] = pd.to_numeric(df['lon'], errors='coerce')
        geo_df = df.dropna(subset=['lat', 'lon'])


        if not geo_df.empty:
            center = [geo_df['lat'].mean(), geo_df['lon'].mean()]
            m = folium.Map(location=center, zoom_start=2)

            for idx, row in geo_df.iterrows():
                folium.CircleMarker(
                    location=[row['lat'], row['lon']],
                    radius=5,
                    color='red',
                    fill=True,
                    fill_color='red',
                    fill_opacity=0.5,
                    popup=str(row.get('ip', ''))
                ).add_to(m)

            st_folium(m, width=700, height=500)

        else:
            st.info("No valid geolocation data available for the map.")

    else:
        st.info("No geolocation data (lat, lon) available to display the scatterplot")