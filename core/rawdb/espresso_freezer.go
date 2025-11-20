package rawdb

// has returns an indicator whether the specified number data is still accessible
// in the freezer table.
func (t *freezerTable) has(number uint64) bool {
	return t.items.Load() > number && t.itemHidden.Load() <= number
}

// HasAncient returns an indicator whether the specified ancient data exists
// in the freezer.
func (f *Freezer) HasAncient(kind string, number uint64) (bool, error) {
	if table := f.tables[kind]; table != nil {
		return table.has(number), nil
	}
	return false, nil
}

func NewFreezerTableConfig(noSnappy bool, prunable bool) freezerTableConfig {
	return freezerTableConfig{noSnappy: prunable}
}
