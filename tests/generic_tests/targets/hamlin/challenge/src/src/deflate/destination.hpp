#pragma once

#include <array>
#include <ostream>

#include "common.hpp"

#include "bit_vector.hpp"

namespace deflate {
  namespace destination {
    class Base{
    public:
      virtual bool operator==(const destination::Base& other) const;
      bool operator!=(const destination::Base& other) const;

      virtual void inspect(std::ostream& out) const;
    };

    class Incomplete : public Base {
    public:
      virtual bool operator==(const destination::Base& other) const override;
      virtual void inspect(std::ostream& out) const override;
    };

    class Invalid : public Base {
    public:
      virtual bool operator==(const destination::Base& other) const override;
      virtual void inspect(std::ostream& out) const override;
    };

    class Literal : public Base {
    public:
      byte val;
      virtual bool operator==(const destination::Base& other) const override;
      virtual void inspect(std::ostream& out) const override;

      constexpr Literal() : val(0) {};
      constexpr Literal(byte l) : val(l) {};
    };

    class EndOfBlock : public Base {
    public:
      virtual bool operator==(const destination::Base& other) const override;
      virtual void inspect(std::ostream& out) const override;
    };

    class Backref : public Base {
    public:
      byte bits;
      uint16_t min;

      constexpr Backref() : bits(0), min(0) {};
      constexpr Backref(byte b, uint16_t m) : bits(b), min(m) {};

      virtual bool operator==(const destination::Base& other) const override;
      virtual void inspect(std::ostream& out) const override;

      uint16_t len(BitVector bv);
    };

    namespace identity {
      constexpr Incomplete incomplete{};
      constexpr Invalid invalid{};
      constexpr EndOfBlock end_of_block{};
    }

    using _literal_table_t = std::array<Literal, 256>;

    constexpr _literal_table_t _make_literal_table() {
      _literal_table_t tbl{};

      for (std::size_t n = 0; n <= 255; n++) {
        tbl[n] = Literal{(byte)n};
      }

      return tbl;
    }

    constexpr _literal_table_t _literal_table = _make_literal_table();

    using _backref_table_t = std::array<Backref, 29>;

    constexpr _backref_table_t _make_backref_table() {
      _backref_table_t tbl{};

      for (std::size_t n = 257; n <= 264; n++) {
        tbl[n - 257] = Backref(0, n - 254);
      }

      for (std::size_t n = 0; n <= 3; n++) {
        tbl[n + 265 - 257] = Backref(1, (n << 1) + 11);
        tbl[n + 269 - 257] = Backref(2, (n << 2) + 19);
        tbl[n + 273 - 257] = Backref(3, (n << 3) + 35);
        tbl[n + 277 - 257] = Backref(4, (n << 4) + 67);
        tbl[n + 281 - 257] = Backref(5, (n << 5) + 131);
      }

      tbl[285 - 257] = Backref(0, 258);

      return tbl;
    }

    constexpr _backref_table_t _backref_table = _make_backref_table();

    using table_t = std::array<const destination::Base*, CODE_COUNT>;

    constexpr table_t _make_destination_table() {
      table_t tbl{};

      for (std::size_t n = 0; n <= 255; n++) {
        tbl[n] = &_literal_table[n];
      }

      tbl[256] = &identity::end_of_block;

      for (std::size_t n = 257; n <= 285; n++) {
        tbl[n] = &_backref_table[n - 257];
      }

      return tbl;
    }

    constexpr table_t fixed_destinations = _make_destination_table();
  }

  using Destination = destination::Base;
}
