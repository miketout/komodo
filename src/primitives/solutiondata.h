// Copyright (c) 2018 Michael Toutonghi
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_SOLUTIONDATA_H
#define BITCOIN_PRIMITIVES_SOLUTIONDATA_H

#include "serialize.h"
#include "uint256.h"
#include "arith_uint256.h"

class CActivationHeight
{
    public:
        static const int32_t MAX_HEIGHT = 0x7fffffff;
        static const int32_t DEFAULT_UPGRADE_HEIGHT = MAX_HEIGHT;
        static const int32_t NUM_VERSIONS = 2;
        static const int32_t SOLUTION_VERUSV2 = 1;
        bool active;
        int32_t heights[NUM_VERSIONS];
        CActivationHeight() : heights{0, DEFAULT_UPGRADE_HEIGHT}, active(true) {}

        void SetActivationHeight(int32_t version, int32_t height)
        {
            assert(version < NUM_VERSIONS && version > 0);
            if (height < MAX_HEIGHT)
            {
                active = true;
            }
            heights[version] = height;
        }

        bool IsActivationHeight(int32_t version, int32_t height)
        {
            assert(version < NUM_VERSIONS && version > 0);
            return active && heights[version] == height;
        }

        int32_t ActiveVersion(int32_t height)
        {
            if (!active)
                return 0;

            int32_t ver = 0;
            for (int32_t i = 0; i < NUM_VERSIONS; i++)
            {
                if (heights[i] > height)
                {
                    break;
                }
                ver = i;
            }
            return ver;
        }
};

class CConstVerusSolutionVector
{
    public:
        static CActivationHeight activationHeight;
        static const bool SOLUTION_SIZE_FIXED = true;

        CConstVerusSolutionVector() {}

        static uint32_t GetVersionByHeight(uint32_t height)
        {
            return activationHeight.ActiveVersion(height);
        }

        uint32_t Version(std::vector<unsigned char> &vch)
        {
            if (activationHeight.ActiveVersion(0x7fffffff) > 0 && vch.size() >= 4)
            {
                return vch[0] + (vch[1] << 8) + (vch[2] << 16) + (vch[3] << 24);
            }
            else
            {
                return 0;
            }
        }

        bool SetVersion(std::vector<unsigned char> &vch, uint32_t v)
        {
            if (activationHeight.active && vch.size() >= 4)
            {
                vch[0] = v & 0xff;
                vch[1] = (v >> 8) & 0xff;
                vch[2] = (v >> 16) & 0xff;
                vch[3] = (v >> 24) & 0xff;
                return true;
            }
            else
            {
                return false;
            }
        }

        bool SetVersionByHeight(std::vector<unsigned char> &vch, uint32_t height)
        {
            return SetVersion(vch, activationHeight.ActiveVersion(height));
        }
};

class CVerusSolutionVector
{
    private:
        static CConstVerusSolutionVector activationHeight;
        std::vector<unsigned char> &vch;

    public:
        static const bool SOLUTION_SIZE_FIXED = true;
        static const uint32_t SOLUTION_SIZE = 1344;

        CVerusSolutionVector(std::vector<unsigned char> &_vch) : vch(_vch) { }

        static uint32_t GetVersionByHeight(uint32_t height)
        {
            return activationHeight.GetVersionByHeight(height);
        }

        uint32_t Version()
        {
            return activationHeight.Version(vch);
        }

        bool SetVersion(uint32_t v)
        {
            activationHeight.SetVersion(vch, v);
        }

        bool SetVersionByHeight(uint32_t height)
        {
            return activationHeight.SetVersionByHeight(vch, height);
        }
};

#endif // BITCOIN_PRIMITIVES_SOLUTIONDATA_H
