"""The guided tour's sample company has to render where real profiles do."""
from shikari.cli import test_data
from shikari.visualization import exposure


def test_sample_profile_builds_an_exposure_map():
    # It once held exposed_services as a list, which the exposure map can't read
    assert exposure.build(test_data._sample_profile())
