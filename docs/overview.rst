Overview
========

Domain Name System in IP architecture is extremely successfull example of a highly scalable distributed database with virtual unlimited capactity to store various types of information.
Such functionality can be of a great benefit in Named Data Networking (NDN) architecture as well.
There could be many potential uses of such a database, including NDN namespace managing (providing authoritative delegation of namespaces), foundation of a public key infrastructure with hierarchical (identity-based) trust model, and many others.
At the same time, the driving force for a DNS implementation in NDN is a specific use: to scale name-based routing.

Scaling name-based routing using DNS (map-n-encap)
--------------------------------------------------

We observe that NDN's routing scalability issue is not new; one could ask a similar question about IP.  
Although IP's address space is finite, it is larger than any of today's router can hold. 
IP solves this problem by address aggregation: at the edge of the Internet, hosts and small networks get addresses from their access providers. 
Since addresses from the same provider can be aggregated into prefixes (i.e., these are provider-aggregatable or PA addresses), routing tables only need to store prefixes instead of individual IP addresses. 
However, over the years there has been an increasing demand for provider-independent (PI) address prefixes. 
Such PI prefixes cannot be aggregated with provider prefixes and must be announced separately, leading to increased routing table size.

Map-n-Encap was proposed long ago to scale IP routing in face of a large number of provider-independent addresses. 
The basic idea is to use a mapping system to map a provider-independent destination address to ISP-specific addresses, and then tunnel the packet (e.g., using IP-in-IP encapsulation) to the destination via the ISP-address.
In this way, the core maintains only a limited number of ISP-specific address prefixes.
This approach is often described as separating the locator and the identifier has led to a number of specific designs including 8+8, LISP, ILNP, and APT, to name a few.
However, due to the difficulties in retrofitting new solutions into the operational Internet, so far none of them has been deployed.

.. figure:: _static/images/map-n-encap-ip.png

    **Map-n-encap example in IP**

    Requesting data from ndnsim.net using map-n-encap can involve the following steps:

    1. Lookup name -> IP address
        - ``ndnsim.net`` => ``1.1.1.1`` and ``2.2.2.2``

    2. Lookup IP -> ISP IP address mapping
        - ``1.1.1.1`` => ``3.0.0.0``, or
        - ``2.2.2.2`` => ``4.0.0.0``

    3. Send IP-IP encapsulated packet
        - outer dst IP: ``3.x.x.x``, inner dst IP: ``1.1.1.1``, or
        - outer dst IP: ``4.x.x.x``, inner dst IP: ``2.2.2.2``


NDN is data-centric, and most of the application use names in a provider-independent way, otherwise they would be required to do renaming whenever service provider changes.
Thus in NDN, the problem of provider-independent name prefixes could be is much worse, but it still can be alleviated applying the same map-n-encap idea in NDN context:
An provider-independed name can be mapped to an ISP-name, which can be carried in the expressed Interests in form of a forwarding hint, alongside the original name.
This essentially moves the scalability issue from the routing to the mapping system, and today's DNS can easily handle this scaling challenge.
As the mapping happens at the edge of the network, it will have no impact on the network core.


.. figure:: _static/images/map-n-encap-ndn.png

    **Map-n-encap example in NDN**

    Requesting /net/ndnsim data using map-n-encap can involve the following steps:

    1. Lookup app name -> "ISP" name (forwarding hint)
        - ``/net/ndnsim`` => ``/net/ucla/cs``
        - ``/net/ndnsim`` => ``/net/telia/latvia``

    2. Send “encapsulated” Interest
        - Interest for ``/net/ndnsim`` with embedded forwarding hint ``/net/ucla/cs``, or
        - Interest for ``/net/ndnsim`` with embedded forwarding hing ``/net/telia/latvia``

NDN forwarding hint
~~~~~~~~~~~~~~~~~~~

Forwarding hint is a concept 
