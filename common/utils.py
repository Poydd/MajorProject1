import matplotlib.pyplot as plt
import pandas as pd
import plotly.graph_objects as go
import seaborn as sns
from plotly.subplots import make_subplots


def load_data(path="../analysis/netflix_titles_nov_2019.csv"):
    df = pd.read_csv(path)
    df["date_added"] = pd.to_datetime(df['date_added'])
    df['year_added'] = df['date_added'].dt.year
    df['month_added'] = df['date_added'].dt.month

    df['season_count'] = df.apply(lambda x: x['duration'].split(" ")[0] if "Season" in x['duration'] else "", axis=1)
    df['duration'] = df.apply(lambda x: x['duration'].split(" ")[0] if "Season" not in x['duration'] else "", axis=1)
    return df


def plot_group_chart(df):
    col = 'type'
    grouped = df[col].value_counts().reset_index()
    trace = go.Pie(labels=grouped[col], values=grouped['count'], pull=[0.05, 0],
                   marker=dict(colors=["#6ad49b", "#a678de"]))
    layout = go.Layout(title="", height=650, legend=dict(x=0.1, y=1.1))
    fig = go.Figure(data=[trace], layout=layout)
    return fig


def years_end_chart(df):
    d1 = df[df["type"] == "TV Show"]
    d2 = df[df["type"] == "Movie"]
    col = "year_added"
    vc1 = d1[col].value_counts().reset_index()
    vc1['count'].apply(lambda x: 100 * x / vc1['count'].sum())
    vc1['percent'] = vc1['count'].apply(lambda x: 100 * x / vc1['count'].sum())
    vc1 = vc1.sort_values(col)
    vc2 = d2[col].value_counts().reset_index()
    vc2['count'].apply(lambda x: 100 * x / vc2['count'].sum())
    vc2['percent'] = vc2['count'].apply(lambda x: 100 * x / vc2['count'].sum())
    vc2 = vc2.sort_values(col)
    trace1 = go.Scatter(x=vc1[col], y=vc1["count"], name="TV Shows", marker=dict(color="#a678de"))
    trace2 = go.Scatter(x=vc2[col], y=vc2["count"], name="Movies", marker=dict(color="#6ad49b"))
    data = [trace1, trace2]
    layout = go.Layout(title="Content added over the years", legend=dict(x=0.1, y=1.1, orientation="h"))
    fig = go.Figure(data, layout=layout)
    return fig

def content_added_chart(df):
    col = 'month_added'
    d1 = df[df["type"] == "TV Show"]
    vc1 = d1[col].value_counts().reset_index()
    vc1 = vc1.sort_values(col)
    trace1 = go.Bar(x=vc1[col], y=vc1["count"], name="TV Shows", marker=dict(color="#a678de"))
    data = [trace1]
    layout = go.Layout(title="In which month, the content is added the most?",
                       legend=dict(x=1.1, y=2.1, orientation="h"))
    fig = go.Figure(data, layout=layout)
    return fig


def season_count_chart(df):
    small = df.sort_values("release_year", ascending=True)
    small = small[small['season_count'] != ""]
    var = small[['shows_movies', "release_year"]][:15]
    col = 'season_count'
    d1 = df[df["type"] == "TV Show"]
    vc1 = d1[col].value_counts().reset_index()
    vc1['count'].apply(lambda x: 100 * x / vc1['count'].sum())
    vc1 = vc1.sort_values(col)
    trace1 = go.Bar(x=vc1[col], y=vc1["count"], name="TV Shows", marker=dict(color="#a678de"))
    data = [trace1]
    layout = go.Layout(title="Seasons", legend=dict(x=0.1, y=1.1, orientation="h"))
    fig = go.Figure(data, layout=layout)
    return fig


def rating_chart(df):
    col = "rating"
    d1 = df[df["type"] == "TV Show"]
    d2 = df[df["type"] == "Movie"]
    vc1 = d1[col].value_counts().reset_index()
    vc2 = d2[col].value_counts().reset_index()
    vc2 = vc2.sort_values(col)
    trace1 = go.Bar(x=vc1[col], y=vc1["count"], name="TV Shows", marker=dict(color="#a678de"))
    trace2 = go.Bar(x=vc2[col], y=vc2["count"], name="Movies", marker=dict(color="#6ad49b"))
    data = [trace1, trace2]
    layout = go.Layout(title="Content added over the years", legend=dict(x=0.1, y=1.1, orientation="h"))
    fig = go.Figure(data, layout=layout)
    return fig


def country_chart(df):
    country = df['country'].value_counts().head(10)
    ct = df['shows_movies'].value_counts()
    plt.pie(data=ct, x=country.values, labels=country.index, autopct='%.f%%')
    plt.title("\n No.of Shows by Country\n", fontsize=18)
    return plt


def country_trace_chart(df):
    from collections import Counter
    def country_trace(country, flag="movie"):
        df["from_us"] = df['country'].fillna("").apply(lambda x: 1 if country.lower() in x.lower() else 0)
        small = df[df["from_us"] == 1]
        if flag == "movie":
            small = small[small["duration"] != ""]
        else:
            small = small[small["season_count"] != ""]
        cast = ", ".join(small['cast'].fillna("")).split(", ")
        tags = Counter(cast).most_common(25)
        tags = [_ for _ in tags if "" != _[0]]

        labels, values = [_[0] + "  " for _ in tags], [_[1] for _ in tags]
        trace = go.Bar(y=labels[::-1], x=values[::-1], orientation="h", name="", marker=dict(color="#a678de"))
        return trace

    traces = []
    titles = ["United States", "", "India", "", "United Kingdom", "Canada", "", "Spain", "", "Japan"]
    for title in titles:
        if title != "":
            traces.append(country_trace(title))

    fig = make_subplots(rows=2, cols=5, subplot_titles=titles)
    fig.add_trace(traces[0], 1, 1)
    fig.add_trace(traces[1], 1, 3)
    fig.add_trace(traces[2], 1, 5)
    fig.add_trace(traces[3], 2, 1)
    fig.add_trace(traces[4], 2, 3)
    fig.add_trace(traces[5], 2, 5)

    fig.update_layout(height=2600, showlegend=False)
    return fig


def indian_director_chart(df):
    from collections import Counter
    small = df[df["type"] == "Movie"]
    small = small[small["country"] == "India"]

    col = "director"
    categories = ", ".join(small[col].fillna("")).split(", ")
    counter_list = Counter(categories).most_common(12)
    counter_list = [_ for _ in counter_list if _[0] != ""]
    labels = [_[0] for _ in counter_list][::-1]
    values = [_[1] for _ in counter_list][::-1]
    trace1 = go.Bar(y=labels, x=values, orientation="h", name="TV Shows", marker=dict(color="orange"))
    data = [trace1]
    layout = go.Layout(title="Movie Directors from India with most content", legend=dict(x=0.1, y=1.1, orientation="h"))
    fig = go.Figure(data, layout=layout)
    return fig


def counts_of_movies_categories(df):
    plt.figure(figsize=(12, 3))
    plt.title("Value Counts of The Categories Variable")
    fig = sns.countplot(y="shows_movies", data=df, order=df.shows_movies.value_counts().iloc[:10].index)
    fig.bar_label(fig.containers[0])
    return fig


def director_value_count(df):
    plt.figure(figsize=(12, 3))
    plt.title("Director")
    fig = sns.countplot(x="director", data=df, order=df.director.value_counts().iloc[:6].index)
    fig.bar_label(fig.containers[0])
    return fig


def counts_of_the_rating(df):
    plt.figure(figsize=(30, 10))
    fig = sns.countplot(x="rating", data=df, hue='type')
    plt.title("Value Counts of The Ratings Variable")
    fig.bar_label(fig.containers[0])
    fig.bar_label(fig.containers[1])
    return fig
