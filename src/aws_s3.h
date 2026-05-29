/*
 * aws_s3.h - AWS S3 via WinHTTP + Signature V4
 * No external SDK required - pure WinAPI
 */
#pragma once
#ifndef AWS_S3_H
#define AWS_S3_H

#include <windows.h>
#include <stdint.h>

/* Maximum sizes */
#define AWS_MAX_KEY_LEN      256
#define AWS_MAX_REGION_LEN    64
#define AWS_MAX_BUCKET_LEN   128
#define AWS_MAX_PATH_LEN    4096
#define AWS_MAX_PROFILE_LEN  128

/* S3 listing entry */
typedef struct S3Object {
    char   key[AWS_MAX_PATH_LEN];
    char   last_modified[32];
    int64_t size;
    int    is_prefix;   /* 1 = folder (common prefix), 0 = file */
    struct S3Object* next;
} S3Object;

typedef struct S3BucketEntry {
    char name[AWS_MAX_BUCKET_LEN];
    char creation_date[32];
    struct S3BucketEntry* next;
} S3BucketEntry;

typedef struct S3Profile {
    char name[AWS_MAX_PROFILE_LEN];
    char access_key_id[AWS_MAX_KEY_LEN];
    char secret_access_key[AWS_MAX_KEY_LEN];
    char region[AWS_MAX_REGION_LEN];
} S3Profile;

/* ─── Profile management ─── */

/* Load all profiles from ~/.aws/credentials
   Returns NULL-terminated array of S3Profile*, caller frees with s3_free_profiles() */
S3Profile** s3_load_profiles(int* out_count);
void         s3_free_profiles(S3Profile** profiles, int count);

/* ─── S3 context ─── */
typedef struct S3Context S3Context;

S3Context* s3_create(const char* access_key_id,
                     const char* secret_access_key,
                     const char* region);
void       s3_destroy(S3Context* ctx);

/* ─── Bucket operations ─── */

/* List all buckets. Returns linked list, caller frees with s3_free_buckets() */
S3BucketEntry* s3_list_buckets(S3Context* ctx);
void           s3_free_buckets(S3BucketEntry* list);

/* Create / delete bucket */
int s3_create_bucket(S3Context* ctx, const char* bucket_name);
int s3_delete_bucket(S3Context* ctx, const char* bucket_name);

/* ─── Object operations ─── */

/* List objects in bucket at prefix. Returns linked list, caller frees with s3_free_objects() */
S3Object* s3_list_objects(S3Context* ctx, const char* bucket,
                           const char* prefix, char delimiter);
void      s3_free_objects(S3Object* list);

/* Download / upload */
int s3_get_object(S3Context* ctx, const char* bucket, const char* key,
                  const char* local_path);
int s3_put_object(S3Context* ctx, const char* bucket, const char* key,
                  const char* local_path);

/* Delete object */
int s3_delete_object(S3Context* ctx, const char* bucket, const char* key);

/* Copy / rename object (S3 copy + delete) */
int s3_copy_object(S3Context* ctx,
                   const char* src_bucket, const char* src_key,
                   const char* dst_bucket, const char* dst_key);

/* Create "folder" (zero-byte object ending with /) */
int s3_put_folder(S3Context* ctx, const char* bucket, const char* key);

#endif /* AWS_S3_H */
