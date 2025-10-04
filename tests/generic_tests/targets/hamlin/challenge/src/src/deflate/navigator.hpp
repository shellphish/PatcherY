#pragma once

class Navigator {
public:
  Navigator(Code c) code(c);

  Destination navigate(BitVector bv);

  Destinatinon destination = {}'

private:
  Code c;
}
