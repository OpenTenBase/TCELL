BASELIB_DIR := dynamic_baselib
MEASURE_DIR := dynamic_measure

.PHONY: all clean $(BASELIB_DIR) $(MEASURE_DIR)

all: $(MEASURE_DIR)

$(MEASURE_DIR): $(BASELIB_DIR)
	@echo "--- Building dynamic_measure ---"
	$(MAKE) -C $(MEASURE_DIR)

$(BASELIB_DIR):
	@echo "--- Building dynamic_baselib ---"
	$(MAKE) -C $(BASELIB_DIR)

clean:
	@echo "--- Cleaning dynamic_baselib ---"
	$(MAKE) -C $(BASELIB_DIR) clean
	@echo "--- Cleaning dynamic_measure ---"
	$(MAKE) -C $(MEASURE_DIR) clean