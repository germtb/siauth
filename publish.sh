#!/bin/bash

set -e

CURRENT_VERSION=$(grep '"version"' siauth-ts/package.json | head -1 | sed 's/.*"version": "\(.*\)".*/\1/')

echo "📦 Current version: $CURRENT_VERSION"
echo ""

if [ -n "$1" ]; then
  VERSION=$1
  if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Version must be in format X.Y.Z (e.g., 0.1.4)"
    exit 1
  fi
else
  IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT_VERSION"

  echo "Select version bump type:"
  echo "1) patch ($CURRENT_VERSION -> $MAJOR.$MINOR.$((PATCH + 1)))"
  echo "2) minor ($CURRENT_VERSION -> $MAJOR.$((MINOR + 1)).0)"
  echo "3) major ($CURRENT_VERSION -> $((MAJOR + 1)).0.0)"
  echo "4) custom"
  echo ""
  read -p "Choice (1-4): " -n 1 -r CHOICE
  echo ""
  echo ""

  case $CHOICE in
    1)
      VERSION="$MAJOR.$MINOR.$((PATCH + 1))"
      ;;
    2)
      VERSION="$MAJOR.$((MINOR + 1)).0"
      ;;
    3)
      VERSION="$((MAJOR + 1)).0.0"
      ;;
    4)
      read -p "Enter custom version: " VERSION
      if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Error: Version must be in format X.Y.Z (e.g., 0.1.4)"
        exit 1
      fi
      ;;
    *)
      echo "Invalid choice"
      exit 1
      ;;
  esac
fi

echo "📦 Publishing version $VERSION"
echo ""

echo "1️⃣  Checking git status..."
if [[ -n $(git status -s) ]]; then
  echo "⚠️  Warning: You have uncommitted changes:"
  git status -s
  read -p "Continue anyway? (y/N) " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
  fi
fi

echo ""
echo "2️⃣  Updating package.json version..."
cd siauth-ts
npm version "$VERSION" --no-git-tag-version
cd ..

echo ""
echo "3️⃣  Committing version bump..."
git add siauth-ts/package.json
git commit -m "bump version to $VERSION"

echo ""
echo "4️⃣  Creating and pushing git tag v$VERSION..."
git tag "v$VERSION"
git push origin main
git push origin "v$VERSION"

echo ""
echo "5️⃣  Publishing to npm..."
cd siauth-ts
npm publish
cd ..

echo ""
echo "✅ Successfully published version $VERSION!"
echo ""
echo "Go module: github.com/germtb/siauth@v$VERSION"
echo "npm package: siauth-ts@$VERSION"
