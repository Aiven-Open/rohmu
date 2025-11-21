# Cassette tests

There are 3 ways to run these tests:

## Running the pre-recorded tests

This allows you to validate that there are no regressions in our code, assuming that the API responses are unchanged.

```shell
python -m pytest --record-mode=none -vv test/playback/test_ovh_s3.py
```

## Re-recording the tests

There is some manual setup of users required and some credentials need to be provided:

- Provide the OVH API credentials (application key, application secret, consumer key) (when running with `--ovh-s3-bucket-existing-setup`)
  - This will automatically configure the bucket and the "user1" policy (descried below) at test setup
- Provide the Admin S3 credentials (access key id, secret access key)
  - This is an S3 user that is allowed to create a bucket whose name is provided via `--ovh-s3-bucket-existing-name`
  - This user is not configured automatically in test setup (for now)
  - For example, it can be configured with the policy in `fixtures/s3-admin-user-policy.json` (manually configured)
- Provide the "User 1" S3 credentials (access key id, secret access key)
  - This is an S3 user that must have the policy defined in `fixtures/s3-user1-user-policy.json`
  - When running with `--ovh-s3-bucket-existing-setup`, the policy of the user is updated automatically
  - This user is not created nor configured automatically in test setup
  - It needs to have "object storage operator" role (manually configured)

This command allows you to record new test cases or update the test cases with new config or upstream changes in the cloud provider.

```shell
# Two spaces before the export statement will avoid storing this in the shell history
  export PYTEST_ADDOPTS='--ovh-s3-admin-access-key-id your-key-id-here --ovh-s3-admin-secret-access-key your-secret-key-here --ovh-s3-user1-access-key-id your-key-id-here --ovh-s3-user1-secret-access-key your-secret-key-here --ovh-api-user1-username user-123456AbCd7E --ovh-api-project deadbeef1234deadbeef --ovh-api-application-key deadbeef1234 --ovh-api-application-secret secret-here --ovh-api-consumer-key consumer-key-here'
python -m pytest --record-mode=rewrite --ovh-s3-bucket-existing-name=my-own-bucket-that-already-exists --ovh-s3-region=eu-west-par -vv test/playback/test_ovh_s3.py
```

If the bucket doesn't already exist, you can let the test setup fixture create it with `--ovh-s3-bucket-existing-setup`:

```shell
# Two spaces before the export statement will avoid storing this in the shell history
  export PYTEST_ADDOPTS='--ovh-s3-admin-access-key-id your-key-id-here --ovh-s3-admin-secret-access-key your-secret-key-here --ovh-s3-user1-access-key-id your-key-id-here --ovh-s3-user1-secret-access-key your-secret-key-here --ovh-api-user1-username user-123456AbCd7E --ovh-api-project deadbeef1234deadbeef --ovh-api-application-key deadbeef1234 --ovh-api-application-secret secret-here --ovh-api-consumer-key consumer-key-here'
python -m pytest --record-mode=rewrite --ovh-s3-bucket-existing-setup --ovh-s3-bucket-existing-name=my-own-bucket-that-will-be-created --ovh-s3-region=eu-west-par -vv test/playback/test_ovh_s3.py
```

It will create a bucket with the name you provide and delete it at teardown.

## Running the tests without recording at all

This needs the same setup as `record-mode=rewrite`.

This allows you to run the test cases against the real cloud provider APIs without reading or writing the recorded cassettes.

```shell
# Two spaces before the export statement will avoid storing this in the shell history
  export PYTEST_ADDOPTS='--ovh-s3-admin-access-key-id your-key-id-here --ovh-s3-admin-secret-access-key your-secret-key-here --ovh-s3-user1-access-key-id your-key-id-here --ovh-s3-user1-secret-access-key your-secret-key-here --ovh-api-user1-username user-123456AbCd7E --ovh-api-project deadbeef1234deadbeef --ovh-api-application-key deadbeef1234 --ovh-api-application-secret secret-here --ovh-api-consumer-key consumer-key-here'
python -m pytest --disable-recording --ovh-s3-bucket-existing-name=my-own-bucket-that-already-exists --ovh-s3-region=eu-west-par -vv test/playback/test_ovh_s3.py
```

Be aware that this will likely skip some assertions as we'll be missing information about the HTTP calls that were not captured/recorded.
