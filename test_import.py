import traceback
try:
    import src.analysis as analysis
    print('IMPORT_OK')
except Exception as e:
    traceback.print_exc()
    print('IMPORT_FAILED')
