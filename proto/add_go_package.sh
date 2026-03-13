#!/bin/bash
# Add go_package option to all proto files that don't have it

set -e

PROTO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Function to add go_package option if it doesn't exist
add_go_package() {
    local file=$1
    local package_path=$2
    local package_name=$3

    # Check if go_package already exists
    if grep -q "option go_package" "$file"; then
        echo "Skipping $file (already has go_package)"
        return
    fi

    # Check if package declaration exists
    if ! grep -q "^package " "$file"; then
        echo "Skipping $file (no package declaration)"
        return
    fi

    echo "Adding go_package to $file"

    # Insert go_package option after the package declaration
    sed -i "/^package /a\\
\\
option go_package = \"github.ibm.com/citius/api/gen/go/$package_path;$package_name\";" "$file"
}

# Process all proto files
echo "Processing types..."
for file in "$PROTO_DIR"/types/*.proto; do
    [ -f "$file" ] || continue
    add_go_package "$file" "types" "types"
done

echo "Processing messages..."
for file in "$PROTO_DIR"/messages/*.proto; do
    [ -f "$file" ] || continue
    add_go_package "$file" "messages" "messages"
done

echo "Processing services..."
for file in "$PROTO_DIR"/services/*.proto; do
    [ -f "$file" ] || continue
    add_go_package "$file" "services" "services"
done

echo "Processing api.proto..."
if [ -f "$PROTO_DIR/api.proto" ]; then
    add_go_package "$PROTO_DIR/api.proto" "api" "api"
fi

echo "Done!"
