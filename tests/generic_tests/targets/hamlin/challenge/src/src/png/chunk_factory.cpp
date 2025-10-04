#include <numeric>
#include <typeinfo>

#include "common.hpp"

#include "chunk_factory.hpp"

using namespace png;

ChunkFactory::ChunkFactory(std::istream& r) {
  Chunk* read_chunk = {};

  do {
    assert(r.good());
    assert(!r.eof());
    read_chunk = new Chunk(r);
    chunks.push_back(read_chunk);
  } while ('IEND' != read_chunk->type);

  materialize_chunks();
}

ChunkFactory::~ChunkFactory() {
  for (Chunk* c : chunks) {
    delete c;
  }
}

void ChunkFactory::inspect(std::ostream& w) {
  w << "ChunkFactory chunks(" << chunks.size() << ") {" << std::endl;
  for (Chunk* c : chunks) {
    w << "\t" << c->type_string() << ": len "
      << c->length << std::endl;
  }
  w << "}" << std::endl;
}

Ihdr* ChunkFactory::ihdr() const {
  Ihdr* ih = dynamic_cast<Ihdr*>(chunks[0]);
  assert(0 != ih);
  return ih;
}

std::vector<Idat*> ChunkFactory::idat() const {
  std::vector<Idat*> dats = {};

  for(Chunk* c : chunks) {
    Idat* i;
    if ((i = dynamic_cast<Idat*>(c))) {
      dats.push_back(i);
    }
  }

  return dats;
}

Plte* ChunkFactory::plte() const {
  for(Chunk* c : chunks) {
    Plte* p;
    if ((p = dynamic_cast<Plte*>(c))) {
      return p;
    }
  }

  return nullptr;
}

std::vector<byte> ChunkFactory::image_data() const {
  std::vector<byte> id = {};
  std::vector<Idat*> idcx = idat();

  assert(idcx.size() > 0);

  auto sizer = [](std::size_t accumulator, Idat* i) {
                 return accumulator + i->length;
               };

  id.reserve(std::accumulate(std::next(idcx.begin()), idcx.end(),
                             0,
                             sizer));

  for (Idat* cur : idcx) {
    std::vector<byte>& to_insert = cur->data;
    id.insert(id.end(), to_insert.begin(), to_insert.end());
  }

  return id;
}

void ChunkFactory::materialize_chunks() {
  for(std::size_t i = 0; i < chunks.size(); i++) {
    Chunk* c = chunks[i];


    if (0 == i) {
      assert('IHDR' == c->type);
    }
    if ((chunks.size() - 1) == i) {
      assert('IEND' == c->type);
    }

    switch (c->type) {
    case 'IHDR':
      assert(0 == i);
      chunks[i] = new Ihdr(*c);
      delete c;
      break;
    case 'PLTE':
      chunks[i] = new Plte(*c);
      delete c;
      break;
    case 'IDAT':
      chunks[i] = new Idat(*c);
      delete c;
      break;
    case 'IEND':
      assert((chunks.size() - 1) == i);
      chunks[i] = new Iend(*c);
      delete c;
      break;
    }
  }
}
