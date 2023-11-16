Reference script comes from:
https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/generate_parameters_grain.sage

In Circom, they use it like this:
(1 input)
sage generate_parameters_grain.sage 1 0 254 2 8 56 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
(2 inputs)
sage generate_parameters_grain.sage 1 0 254 3 8 57 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
...
    