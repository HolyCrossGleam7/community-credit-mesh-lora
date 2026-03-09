#pragma once

// Region selection (compile-time)
#define REGION_US915 1
// #define REGION_EU868 1

#if defined(REGION_US915) && defined(REGION_EU868)
#error "Choose only one region"
#endif

#if !defined(REGION_US915) && !defined(REGION_EU868)
#define REGION_US915 1
#endif

#if defined(REGION_US915)
static const long LORA_FREQUENCY_HZ = 915000000;
#elif defined(REGION_EU868)
static const long LORA_FREQUENCY_HZ = 868000000;
#endif
