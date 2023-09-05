import sys
import broker

# Setup endpoint and connect to Zeek.
with broker.Endpoint() as ep, \
     ep.make_subscriber("zeek_ml/content") as sub, \
     ep.make_status_subscriber(True) as ss:

    ep.peer("127.0.0.1", 1337)

    # Wait until connection is established.
    st = ss.get()

    if not (type(st) == broker.Status and st.code() == broker.SC.EndpointDiscovered):
        print("Connection error!!")
        sys.exit(1)

    print("Connected!")

    while True:
        (tag, data) = sub.get()
        print(broker.zeek.Event(data).args())
