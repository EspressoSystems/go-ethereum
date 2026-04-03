package rawdb

func NewEspressoTableConfig(tables map[string]bool) map[string]freezerTableConfig {
	result:= make(map[string]freezerTableConfig)
	for key, value := range tables {
		result[key] = freezerTableConfig{noSnappy: value, prunable: true}
	}
	return result
}
