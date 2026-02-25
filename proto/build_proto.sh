#!/bin/bash
# Build script for generating gRPC and REST gateway code from proto files

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Building CaaS Protobuf files with REST annotations${NC}"

# Directory setup
PROTO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$PROTO_DIR")"
GEN_DIR="${PROJECT_ROOT}/gen"
GO_OUT="${GEN_DIR}/go"
OPENAPI_OUT="${GEN_DIR}/openapi"

# Create output directories
mkdir -p "$GO_OUT"
mkdir -p "$OPENAPI_OUT"

echo -e "${YELLOW}Output directories:${NC}"
echo "  Go: $GO_OUT"
echo "  OpenAPI: $OPENAPI_OUT"

# Check if protoc is installed
if ! command -v protoc &> /dev/null; then
    echo -e "${RED}Error: protoc not found. Please install Protocol Buffer compiler.${NC}"
    echo "Visit: https://grpc.io/docs/protoc-installation/"
    exit 1
fi

# Check if required generators are installed
echo -e "${YELLOW}Checking required tools...${NC}"

MISSING_TOOLS=0

if ! command -v protoc-gen-go &> /dev/null; then
    echo -e "${RED}Missing: protoc-gen-go${NC}"
    echo "Install with: go install google.golang.org/protobuf/cmd/protoc-gen-go@latest"
    MISSING_TOOLS=1
fi

if ! command -v protoc-gen-go-grpc &> /dev/null; then
    echo -e "${RED}Missing: protoc-gen-go-grpc${NC}"
    echo "Install with: go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest"
    MISSING_TOOLS=1
fi

# Optional: gRPC-Gateway (for REST support)
if ! command -v protoc-gen-grpc-gateway &> /dev/null; then
    echo -e "${YELLOW}Optional: protoc-gen-grpc-gateway not found (needed for REST gateway)${NC}"
    echo "Install with: go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@latest"
fi

if ! command -v protoc-gen-openapiv2 &> /dev/null; then
    echo -e "${YELLOW}Optional: protoc-gen-openapiv2 not found (needed for OpenAPI spec)${NC}"
    echo "Install with: go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@latest"
fi

if [ $MISSING_TOOLS -eq 1 ]; then
    echo -e "${RED}Please install missing required tools before continuing.${NC}"
    exit 1
fi

echo -e "${GREEN}All required tools found!${NC}\n"

# ============================================================================
# Use buf generate for dependency resolution (buf/validate, googleapis, etc.)
# ============================================================================

# Check if buf is installed
if ! command -v buf &> /dev/null; then
    echo -e "${RED}Error: buf not found. Please install the Buf CLI.${NC}"
    echo "Visit: https://buf.build/docs/installation"
    exit 1
fi

echo -e "${GREEN}Compiling proto files with buf generate...${NC}\n"

# Update buf dependencies
echo -e "${YELLOW}Updating buf dependencies...${NC}"
cd "$PROTO_DIR"
buf dep update

# Generate code using buf (resolves buf/validate and other BSR dependencies)
echo -e "${YELLOW}Running buf generate...${NC}"
buf generate

echo -e "\n${GREEN}Build completed successfully!${NC}\n"
echo -e "${YELLOW}Generated files:${NC}"
echo "  Go code: $GO_OUT"
echo "  OpenAPI: $OPENAPI_OUT"

# Check if OpenAPI spec was generated
if [ -f "$OPENAPI_OUT/caas.swagger.json" ]; then
    echo -e "\n${GREEN}OpenAPI specification generated: $OPENAPI_OUT/caas.swagger.json${NC}"
    echo "  You can view this with Swagger UI or import into Postman"
fi

echo -e "\n${GREEN}Done!${NC}"
