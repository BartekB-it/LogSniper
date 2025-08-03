import streamlit as st
import os
import json
import pandas as pd
import matplotlib.pyplot as plt

st.title("LogSniper Results Dashboard")

files = [f for f in os.listdir("results") if f.endswith(".json")]
selected_file = st.selectbox("Wybierz plik wyników:", files)

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

    classification_filter = st.selectbox("Filtruj dane według klasyfikacji:", classification_counts.index)
    filtered_df = df[df['classification'] == classification_filter]

    st.write(f"Wyniki dla klasyfikacji: {classification_filter}")
    st.dataframe(filtered_df)