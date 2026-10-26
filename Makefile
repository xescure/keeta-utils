# Every build artifact is defined here; package.json only exposes the binaries
# of the npm packages to "npm run".

CLEAN_GOALS := $(filter clean,$(MAKECMDGOALS))
OTHER_GOALS := $(filter-out clean,$(MAKECMDGOALS))

ifneq ($(and $(CLEAN_GOALS),$(OTHER_GOALS)),)

# Under -j make would stat the targets before "clean" deletes them, and judge
# them up to date. Cleaning in a make of its own first gives the rest a fresh
# view of the tree.
.PHONY: run-mixed-goals $(MAKECMDGOALS)
$(MAKECMDGOALS): run-mixed-goals
	@:

run-mixed-goals:
	$(MAKE) $(CLEAN_GOALS)
	$(MAKE) $(OTHER_GOALS)

else

# The directories are prerequisites too: adding or removing a file changes the
# directory, which a list of the files alone would not notice.
SOURCES := $(shell find src)

all: build

build: dist/.done

node_modules/.done: package.json package-lock.json
	rm -rf node_modules
	npm clean-install --ignore-scripts
	@touch $@

# The build starts from an empty directory, so a removed source leaves nothing
# behind; without the stamp the directory may be partial.
dist/.done: $(SOURCES) tsconfig.json tsconfig.build.json package-lock.json node_modules/.done
	rm -rf dist
	npm run tsc -- -p tsconfig.build.json
	@touch $@

# The type check covers the tests, which the build leaves out, and writes
# nothing, so it runs beside the tests and the build under -j.
typecheck: node_modules/.done
	npm run tsc -- --noEmit -p tsconfig.json

test: node_modules/.done
	npm run vitest -- run

check: typecheck test

clean:
	rm -rf dist

.PHONY: all build typecheck test check clean

endif
