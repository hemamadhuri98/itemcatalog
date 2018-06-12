from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Store, Base, Ornament, User

engine = create_engine('sqlite:///store.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()
User1 = User(name="hema", email="15pa1a0462@vishnu.edu.in")

store1 = Store(user_id=1,name="Joyalukas")
session.add(store1)
session.commit()

ornament1 = Ornament(name="Gold chain", description="made with gold", price="$150",
                   ornamenttype="Gold", store=store1)

session.add(ornament1)
session.commit()

ornament2 = Ornament(name="Platinum Ring", description="with a letter design",
                   price="$450", ornamenttype="Platinum", store=store1)

session.add(ornament2)
session.commit()

ornament3 = Ornament(name="Platinum Necklace", description="with leaves design",
                   price="$950", ornamenttype="Platinum", store=store1)

session.add(ornament3)
session.commit()

store2 = Store(user_id=1,name="Malbar")
session.add(store2)
session.commit()

ornament1 = Ornament(name="Silver Plate", description="designed with gold flower",
                   price="$200", ornamenttype="Silver", store=store2)

session.add(ornament1)
session.commit()

ornament2 = Ornament(name="Gold Earrings", description="designed with stones",
                   price="$500", ornamenttype="Gold", store=store2)

session.add(ornament2)
session.commit()

ornament3 = Ornament(name="Platinum chain", description="adjustable",
                   price="$900", ornamenttype="Platinum", store=store1)

session.add(ornament3)
session.commit()

store3 = Store(user_id=1,name="Tanishq")
session.add(store3)
session.commit()

ornamentt1 = Ornament(name="Gold Plate", description="Heavy",
                   price="$650", ornamenttype="Gold", store=store3)

session.add(ornament1)
session.commit()

ornament2 = Ornament(name="Silver ring", description="with a single diamond",
                   price="$550", ornamenttype="Silver", store=store1)

session.add(ornament2)
session.commit()

ornament3 = Ornament(name="Gold Necklace", description="designed with locket",
                   price="$750", ornamenttype="Gold", store=store1)

session.add(ornament3)
session.commit()

store4 = Store(user_id=1,name="J&J")
session.add(store4)
session.commit()

ornament1 = Ornament(name="Platinum Earrings", description="simple",
                   price="$700", ornamenttype="Platinum", store=store4)

session.add(ornament1)
session.commit()

ornament2 = Ornament(name="Couple Rings", description="designed with heart symbol",
                   price="$750", ornamenttype="Silver", store=store4)

session.add(ornament2)
session.commit()

ornament3 = Ornament(name="Silver Bowl", description="well designed",
                   price="$350", ornamenttype="Silver", store=store4)

session.add(ornament3)
session.commit()

print("added ornament details!")
