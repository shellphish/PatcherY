#include "distance_destination.hpp"

using namespace deflate;

void DistanceDestination::inspect(std::ostream& o) const {
  o << "DistanceDestination bits(" << (int)extra << ") min(" << min << ")"
    << std::endl;
}
