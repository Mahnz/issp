# Implement an Attribute-Based Access Control (ABAC) scheme. Directives:
#
# - Assume that all users are already authenticated.
# - Users have the following attributes:
#   - "age" (int): the user's age.
#   - "premium" (bool): whether the user is a premium user.
# - Objects have the following attributes:
#   - "rating" (str): the movie's rating ("G", "PG-13", "R").
#   - "year" (int): the movie's release year.
# - The environment has the following attributes:
#   - "date" (datetime): the current date.
# - The following attribute assignments are in effect:
#   - Alice: age=12, premium=False
#   - Bob: age=11, premium=True
#   - Carl: age=14, premium=False
#   - Diana: age=15, premium=True
#   - Evan: age=18, premium=False
#   - Frank: age=25, premium=True
#   - toy_story.mov: rating="G", year=1995
#   - elemental.mov: rating="G", year=2023
#   - interstellar.mov: rating="PG-13", year=2014
#   - dune_2.mov: rating="PG-13", year=2024
#   - ex_machina.mov: rating="R", year=2014
#   - oppenheimer.mov: rating="R", year=2023
# - The following policies are in effect:
#   - Rating policy: a user can watch a movie if they are old enough for its rating.
#                    (G: no restrictions, PG-13: 13+, R: 17+)
#   - Release policy: movies released in 2023 or later can only be watched by premium users.
#   - Promo policy: all movies can be watched by any user between December 25 and December 31.
# - Make sure to implement reasonable defaults.
#
# Hint: implement policies as functions that take the subject, object, and environment attributes as
#       arguments and return a boolean, and store them in a dictionary that acts as a policy store.


import datetime
import itertools

from issp import Actor, Channel, FileServer, log


class Server(FileServer):
    def __init__(self, name: str, *, quiet: bool = False) -> None:
        super().__init__(name, quiet=quiet)

        self.file_data["toy_story.mov"] = b"This is a G-rated old movie."
        self.file_data["elemental.mov"] = b"This is a G-rated new movie."
        self.file_data["interstellar.mov"] = b"This is a PG-13-rated old movie."
        self.file_data["dune_2.mov"] = b"This is a PG-13-rated new movie."
        self.file_data["ex_machina.mov"] = b"This is an R-rated old movie."
        self.file_data["oppenheimer.mov"] = b"This is an R-rated new movie."

        # Attributes

        self.subject_attributes = {
            "Alice": {"age": 12, "premium": False},
            "Bob": {"age": 11, "premium": True},
            "Carl": {"age": 14, "premium": False},
            "Diana": {"age": 15, "premium": True},
            "Evan": {"age": 18, "premium": False},
            "Frank": {"age": 25, "premium": True},
        }

        self.object_attributes = {
            "toy_story.mov": {"rating": "G", "year": 1995},
            "elemental.mov": {"rating": "G", "year": 2023},
            "interstellar.mov": {"rating": "PG-13", "year": 2014},
            "dune_2.mov": {"rating": "PG-13", "year": 2024},
            "ex_machina.mov": {"rating": "R", "year": 2014},
            "oppenheimer.mov": {"rating": "R", "year": 2023},
        }

        self.environment_attributes = {
            "date": datetime.datetime.now(tz=datetime.UTC),
        }

        # Policies

        def rating_policy(s: dict, o: dict, _: dict) -> bool:
            pg_age = 13
            r_age = 17
            return (
                o["rating"] == "G"
                or (o["rating"] == "PG-13" and s["age"] >= pg_age)
                or (o["rating"] == "R" and s["age"] >= r_age)
            )

        def release_policy(s: dict, o: dict, _: dict) -> bool:
            new_movie_year = 2023
            return o["year"] < new_movie_year or s["premium"]

        def promo_policy(_1: dict, _2: dict, e: dict) -> bool:
            cur_date: datetime.datetime = e["date"]
            promo_start = datetime.datetime(cur_date.year, 12, 25, tzinfo=datetime.UTC)
            promo_end = datetime.datetime(cur_date.year, 12, 31, tzinfo=datetime.UTC)
            return promo_start <= cur_date <= promo_end

        def access_policy(s: dict, o: dict, e: dict) -> bool:
            return rating_policy(s, o, e) and (release_policy(s, o, e) or promo_policy(s, o, e))

        self.policy_store = {
            "rating": rating_policy,
            "release": release_policy,
            "promo": promo_policy,
            "watch": access_policy,
        }

    def authorize(self, user: str, file: str, action: str) -> bool:
        if action != "read":
            return False
        return self.policy_store["watch"](
            self.subject_attributes[user],
            self.object_attributes[file],
            self.environment_attributes,
        )


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    carl = Actor("Carl")
    diana = Actor("Diana")
    evan = Actor("Evan")
    frank = Actor("Frank")
    server = Server("Server")
    channel = Channel()

    users = (alice, bob, carl, diana, evan, frank)
    paths = (
        "toy_story.mov",
        "elemental.mov",
        "interstellar.mov",
        "dune_2.mov",
        "ex_machina.mov",
        "oppenheimer.mov",
    )

    for path, user in itertools.product(paths, users):
        log.info("--- %s watches %s ---", user.name, path)
        message = {"user": user.name, "action": "read", "path": path}
        server.exchange(channel, user, message)


if __name__ == "__main__":
    main()
